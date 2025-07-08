#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include "bootid.h"
#include "crypto.h"
#include "exfat.h"
#include "ntfs.h"
#include <openssl/evp.h>
#include <openssl/aes.h>

#define PAGE_SIZE 4096
#define BUFFER_SIZE (PAGE_SIZE * 256)
#define MAX_PATH_LENGTH 256

char* g_output_filename = NULL;

#ifdef _WIN32
#include <windows.h>
#define unlink _unlink
#define PATH_SEPARATOR "\\"
#else
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#define PATH_SEPARATOR "/"
#endif

static int make_parent_dirs(const char* path) {
    char tmp[MAX_PATH_LENGTH];
    size_t len = strlen(path);
    if (len >= MAX_PATH_LENGTH) return -1;
    strcpy(tmp, path);

#ifdef _WIN32
    char sep = '\\';
#else
    char sep = '/';
#endif
    char* p = strrchr(tmp, sep);
    if (!p) return 0;
    *p = '\0';

    if (strlen(tmp) > 0) {
        make_parent_dirs(tmp);
#ifdef _WIN32
        CreateDirectoryA(tmp, NULL);
#else
        mkdir(tmp, 0755);
#endif
    }
    return 0;
}

int process_file(const char* path, bool extract_fs, const char* output_dir) {
    uint8_t* bootid_bytes = malloc(96);
    uint8_t* read_buffer = malloc(BUFFER_SIZE);
    uint8_t* decrypted_buffer = malloc(BUFFER_SIZE);
    uint8_t iv[16];
    uint8_t page_iv[16];
    uint8_t key[16];

    if (!bootid_bytes || !read_buffer || !decrypted_buffer) {
        printf("Memory allocation failed\n");
        free(bootid_bytes);
        free(read_buffer);
        free(decrypted_buffer);
        return 1;
    }

    FILE* file = fopen(path, "rb");
    if (!file) {
        perror(path);
        free(bootid_bytes);
        free(read_buffer);
        free(decrypted_buffer);
        return 1;
    }

    if (fread(bootid_bytes, 1, 96, file) != 96) {
        printf("Could not read BootId from %s\n", path);
        fclose(file);
        free(bootid_bytes);
        free(read_buffer);
        free(decrypted_buffer);
        return 1;
    }

    uint8_t decrypted_bootid_bytes[96];
    int out_len = 0;

    EVP_CIPHER_CTX* bootid_ctx = EVP_CIPHER_CTX_new();
    if (!bootid_ctx) {
        printf("Could not create cipher context\n");
        fclose(file);
        free(bootid_bytes);
        free(read_buffer);
        free(decrypted_buffer);
        return 1;
    }

    EVP_DecryptInit_ex(bootid_ctx, EVP_aes_128_cbc(), NULL, BOOTID_KEY, BOOTID_IV);
    EVP_CIPHER_CTX_set_padding(bootid_ctx, 0);

    if (!EVP_DecryptUpdate(bootid_ctx, decrypted_bootid_bytes, &out_len, bootid_bytes, 96)) {
        printf("Could not decrypt BootId in %s\n", path);
        EVP_CIPHER_CTX_free(bootid_ctx);
        fclose(file);
        free(bootid_bytes);
        free(read_buffer);
        free(decrypted_buffer);
        return 1;
    }

    int final_len = 0;
    if (!EVP_DecryptFinal_ex(bootid_ctx, decrypted_bootid_bytes + out_len, &final_len)) {
        printf("Could not finalize decryption\n");
        EVP_CIPHER_CTX_free(bootid_ctx);
        fclose(file);
        free(bootid_bytes);
        free(read_buffer);
        free(decrypted_buffer);
        return 1;
    }
    EVP_CIPHER_CTX_free(bootid_ctx);

    BootId bootid;
    memcpy(&bootid, decrypted_bootid_bytes, sizeof(BootId));

    if (bootid.container_type != CONTAINER_TYPE_OS &&
        bootid.container_type != CONTAINER_TYPE_APP &&
        bootid.container_type != CONTAINER_TYPE_OPTION) {
        printf("Unknown container type %d\n", bootid.container_type);
        fclose(file);
        free(bootid_bytes);
        free(read_buffer);
        free(decrypted_buffer);
        return 1;
    }

    char target_timestamp_str[20];
    format_timestamp(&bootid.target_timestamp, target_timestamp_str, sizeof(target_timestamp_str));

    char os_id[4];
    char game_id[5];
    memcpy(os_id, bootid.os_id, 3);
    os_id[3] = '\0';
    memcpy(game_id, bootid.game_id, 4);
    game_id[4] = '\0';

    const char* id = (bootid.container_type == CONTAINER_TYPE_OS) ? os_id : game_id;

    GameKeys keys;
    bool got_keys = false;
    if (bootid.container_type == CONTAINER_TYPE_OS || bootid.container_type == CONTAINER_TYPE_APP) {
        got_keys = get_game_keys(id, &keys);
    }
    else {
        memcpy(keys.key, OPTION_KEY, 16);
        memcpy(keys.iv, OPTION_IV, 16);
        keys.has_iv = true;
        got_keys = true;
    }

    if (!got_keys) {
        printf("Decryption key invalid or not found.\n");
        fclose(file);
        free(bootid_bytes);
        free(read_buffer);
        free(decrypted_buffer);
        return 1;
    }

    uint64_t data_offset = bootid.header_block_count * bootid.block_size;

    bool has_iv = false;
    memcpy(key, keys.key, 16);

    if (bootid.use_custom_iv) {
        has_iv = false;
    }
    else {
        has_iv = keys.has_iv;
        if (has_iv) {
            memcpy(iv, keys.iv, 16);
        }
    }

    if (!has_iv) {
        if (fseek(file, data_offset, SEEK_SET) != 0) {
            perror("fseek");
            fclose(file);
            free(bootid_bytes);
            free(read_buffer);
            free(decrypted_buffer);
            return 1;
        }

        size_t read_size = fread(read_buffer, 1, PAGE_SIZE, file);
        if (read_size != PAGE_SIZE) {
            perror("fread");
            fclose(file);
            free(bootid_bytes);
            free(read_buffer);
            free(decrypted_buffer);
            return 1;
        }

        if (bootid.container_type == CONTAINER_TYPE_OPTION) {
            if (!calculate_file_iv(key, EXFAT_HEADER, read_buffer, iv)) {
                printf("Could not calculate file IV\n");
                fclose(file);
                free(bootid_bytes);
                free(read_buffer);
                free(decrypted_buffer);
                return 1;
            }
        }
        else {
            if (!calculate_file_iv(key, NTFS_HEADER, read_buffer, iv)) {
                printf("Could not calculate file IV\n");
                fclose(file);
                free(bootid_bytes);
                free(read_buffer);
                free(decrypted_buffer);
                return 1;
            }
        }
        has_iv = true;
    }

    char* output_filename = malloc(MAX_PATH_LENGTH);
    if (!output_filename) {
        printf("Memory allocation failed\n");
        fclose(file);
        free(bootid_bytes);
        free(read_buffer);
        free(decrypted_buffer);
        return 1;
    }

    char file_name[MAX_PATH_LENGTH];
    if (bootid.container_type == CONTAINER_TYPE_OS) {
        snprintf(file_name, MAX_PATH_LENGTH, "%s_%04d%02d%02d_%s_%d.ntfs",
            os_id,
            bootid.os_version.major,
            bootid.os_version.minor,
            bootid.os_version.release,
            target_timestamp_str,
            bootid.sequence_number);
    }
    else if (bootid.container_type == CONTAINER_TYPE_APP) {
        if (bootid.sequence_number > 0) {
            snprintf(file_name, MAX_PATH_LENGTH, "%s_%d%02d%02d_%s_%d_%d%02d%02d.ntfs",
                game_id,
                bootid.target_version.version.major,
                bootid.target_version.version.minor,
                bootid.target_version.version.release,
                target_timestamp_str,
                bootid.sequence_number,
                bootid.source_version.major,
                bootid.source_version.minor,
                bootid.source_version.release);
        }
        else {
            snprintf(file_name, MAX_PATH_LENGTH, "%s_%d%02d%02d_%s_%d.ntfs",
                game_id,
                bootid.target_version.version.major,
                bootid.target_version.version.minor,
                bootid.target_version.version.release,
                target_timestamp_str,
                bootid.sequence_number);
        }
    }
    else if (bootid.container_type == CONTAINER_TYPE_OPTION) {
        char option_str[5];
        memcpy(option_str, bootid.target_version.option, 4);
        option_str[4] = '\0';
        snprintf(file_name, MAX_PATH_LENGTH, "%s_%s_%s_%d.exfat",
            game_id,
            option_str,
            target_timestamp_str,
            bootid.sequence_number);
    }

    if (output_dir && output_dir[0] != '\0') {
#ifdef _WIN32
        snprintf(output_filename, MAX_PATH_LENGTH, "%s\\%s", output_dir, file_name);
#else
        snprintf(output_filename, MAX_PATH_LENGTH, "%s/%s", output_dir, file_name);
#endif
    }
    else {
        snprintf(output_filename, MAX_PATH_LENGTH, "%s", file_name);
    }

    make_parent_dirs(output_filename);

    FILE* output_file = fopen(output_filename, "wb");
    if (!output_file) {
        perror(output_filename);
        free(output_filename);
        fclose(file);
        free(bootid_bytes);
        free(read_buffer);
        free(decrypted_buffer);
        return 1;
    }

    uint64_t output_size = (bootid.block_count - bootid.header_block_count) * bootid.block_size;

    if (fseek(file, data_offset, SEEK_SET) != 0) {
        perror("fseek");
        fclose(file);
        fclose(output_file);
        free(bootid_bytes);
        free(read_buffer);
        free(decrypted_buffer);
        free(output_filename);
        return 1;
    }

    EVP_CIPHER_CTX* page_ctx = EVP_CIPHER_CTX_new();
    if (!page_ctx) {
        printf("Could not create cipher context\n");
        fclose(file);
        fclose(output_file);
        free(bootid_bytes);
        free(read_buffer);
        free(decrypted_buffer);
        free(output_filename);
        return 1;
    }
    EVP_DecryptInit_ex(page_ctx, EVP_aes_128_cbc(), NULL, key, NULL);
    EVP_CIPHER_CTX_set_padding(page_ctx, 0);

    printf("\nDecrypting file...\n");
    time_t last_update_time = time(NULL);
    int last_percentage = -1;

    uint64_t total_bytes_read = 0;
    uint64_t bytes_remaining = output_size;

    while (bytes_remaining > 0) {
        size_t chunk_size = (bytes_remaining > BUFFER_SIZE) ? BUFFER_SIZE : (size_t)bytes_remaining;

        size_t read_size = fread(read_buffer, 1, chunk_size, file);
        if (read_size != chunk_size) {
            if (feof(file)) {
                printf("\nUnexpected end of file\n");
            }
            else {
                perror("\nread_chunk");
            }
            break;
        }

        size_t offset = 0;
        while (offset < read_size) {
            size_t block_size = (read_size - offset > PAGE_SIZE) ? PAGE_SIZE : (read_size - offset);

            uint64_t file_offset = total_bytes_read + offset;
            calculate_page_iv(file_offset, iv, page_iv);  // Generate unique IV for each 4KB page

            EVP_DecryptInit_ex(page_ctx, NULL, NULL, NULL, page_iv);

            int out_len1 = 0, out_len2 = 0;
            if (!EVP_DecryptUpdate(page_ctx, decrypted_buffer + offset, &out_len1, read_buffer + offset, block_size)) {
                printf("\nCould not decrypt data\n");
                break;
            }
            if (!EVP_DecryptFinal_ex(page_ctx, decrypted_buffer + offset + out_len1, &out_len2)) {
                printf("\nCould not finalize decryption\n");
                break;
            }
            if (out_len1 + out_len2 != (int)block_size) {
                printf("\nDecrypted data size mismatch\n");
                break;
            }
            offset += block_size;
        }

        if (fwrite(decrypted_buffer, 1, read_size, output_file) != read_size) {
            perror("\nfwrite");
            break;
        }

        total_bytes_read += read_size;
        bytes_remaining -= read_size;

        time_t current_time = time(NULL);
        if (current_time != last_update_time) {
            int percentage = (int)((total_bytes_read * 100) / output_size);
            if (percentage != last_percentage) {
                printf("\rProgress: %d%%    ", percentage);  // Extra spaces to clear line
                fflush(stdout);
                last_percentage = percentage;
            }
            last_update_time = current_time;
        }
    }

    printf("\rProgress: 100%%    \n");

    EVP_CIPHER_CTX_free(page_ctx);

    fclose(file);
    fclose(output_file);

    printf("Decryption finalized: %s\n", output_filename);

    if (extract_fs) {
        if (g_output_filename) {
            free(g_output_filename);
        }
        g_output_filename = output_filename;
    }
    else {
        free(output_filename);
    }

    free(bootid_bytes);
    free(read_buffer);
    free(decrypted_buffer);

    return 0;
}

int main(int argc, char* argv[]) {
    bool extract_fs = true;
    bool clean_intermediate = false;
    int start_index = 1;
    char output_dir[MAX_PATH_LENGTH] = { 0 };

    if (argc < 2) {
        printf("usage: unsegaREBORN [-no] [--fsout <output_dir>] [--clean] <input_file1> [<input_file2> ...]\n");
        printf("  -no         Do not extract filesystem archives after decryption\n");
        printf("  --fsout     Specify output directory for decrypted files\n");
        printf("  --clean     Delete intermediate .exfat/.ntfs files after extraction (only if -no not present)\n");
        return 0;
    }

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-no") == 0) {
            extract_fs = false;
            start_index = i + 1;
        }
        else if (strcmp(argv[i], "--fsout") == 0 && i + 1 < argc) {
            strncpy(output_dir, argv[i + 1], MAX_PATH_LENGTH - 1);
            output_dir[MAX_PATH_LENGTH - 1] = '\0';
            i++;
            start_index = i + 1;
        }
        else if (strcmp(argv[i], "--clean") == 0) {
            clean_intermediate = true;
            start_index = i + 1;
        }
        else if (argv[i][0] != '-') {
            start_index = i;
            break;
        }
    }

    if (start_index >= argc) {
        printf("No input files specified\n");
        return 1;
    }

    for (int i = start_index; i < argc; ++i) {
        const char* file_path = argv[i];
        printf("Processing file: %s\n", file_path);

        if (process_file(file_path, extract_fs, output_dir) == 0) {
            if (extract_fs && g_output_filename) {
                char output_fs_dir[MAX_PATH_LENGTH];
                if (output_dir && output_dir[0] != '\0') {
                    strncpy(output_fs_dir, output_dir, sizeof(output_fs_dir) - 1);
                    output_fs_dir[sizeof(output_fs_dir) - 1] = '\0';
                }
                else {
                    strncpy(output_fs_dir, g_output_filename, sizeof(output_fs_dir) - 1);
                    output_fs_dir[sizeof(output_fs_dir) - 1] = '\0';
                    char* ext = strrchr(output_fs_dir, '.');
                    if (ext) *ext = '\0';
                }

                bool extracted = false;
                bool is_exfat = strstr(g_output_filename, ".exfat") != NULL;
                bool is_ntfs = strstr(g_output_filename, ".ntfs") != NULL;

                if (is_exfat) {
                    ExfatContext ctx;
                    if (exfat_init(&ctx, g_output_filename)) {
                        if (exfat_extract_all(&ctx, output_fs_dir)) {
                            printf("\nExFAT extraction completed successfully\n");
                            extracted = true;
                        }
                        else {
                            printf("\nFailed to extract ExFAT archive\n");
                        }
                        exfat_close(&ctx);
                    }
                    else {
                        printf("\nFailed to initialize ExFAT context\n");
                    }
                }
                else if (is_ntfs) {
                    NTFSContext ctx = { 0 };
                    if (ntfs_init(&ctx, g_output_filename, output_fs_dir)) {
                        printf("\nExtracting NTFS archive...\n");

                        if (ntfs_extract_all(&ctx)) {
                            printf("\nNTFS extraction completed successfully\n");
                            extracted = true;

                            char vhd_path[MAX_PATH_LENGTH];
                            bool found_child = false;

                            for (int vhd_num = 0; vhd_num < 10; vhd_num++) {
                                snprintf(vhd_path, sizeof(vhd_path), "%s%sinternal_%d.vhd",
                                    output_fs_dir, PATH_SEPARATOR, vhd_num);

                                FILE* test = fopen(vhd_path, "rb");
                                if (!test) continue;
                                fclose(test);

                                if (vhd_num > 0) {
                                    printf("\nChild internal VHD identified, finalizing process.\n");
                                    found_child = true;
                                    break;
                                }

                                NTFSContext vhd_ctx = { 0 };
                                if (ntfs_init(&vhd_ctx, vhd_path, output_fs_dir)) {
                                    printf("\nExtracting from internal VHD...\n");
                                    if (ntfs_extract_all(&vhd_ctx)) {
                                        printf("\nInternal VHD extraction completed successfully\n");
                                    }
                                    else {
                                        printf("\nFailed to extract VHD contents\n");
                                    }
                                    ntfs_close(&vhd_ctx);
                                }
                                else {
                                    printf("\nFailed to open internal VHD\n");
                                }
                                break;
                            }
                        }
                        else {
                            printf("\nFailed to extract NTFS archive\n");
                        }
                        ntfs_close(&ctx);
                    }
                    else {
                        printf("\nFailed to initialize NTFS context\n");
                    }
                }
                else {
                    printf("\nUnknown filesystem type for file %s\n", g_output_filename);
                }

                if (clean_intermediate && extracted && (is_exfat || is_ntfs)) {
                    if (unlink(g_output_filename) == 0) {
                        printf("Intermediate file %s deleted (--clean)\n", g_output_filename);
                    }
                    else {
                        printf("Warning: failed to delete intermediate file %s\n", g_output_filename);
                    }
                }

                free(g_output_filename);
                g_output_filename = NULL;
            }
        }
        else {
            printf("Failed to process %s\n", file_path);
        }
    }

    if (g_output_filename) {
        free(g_output_filename);
    }

    return 0;
}