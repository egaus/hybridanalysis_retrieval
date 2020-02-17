import shutil
import argparse
import logging
import os
import time
import glob
import pyzipper
import gzip
import hashlib

def get_files(monitor_directory, days_back):
    glob_pattern = os.path.join(monitor_directory, '**/*')
    sub_dir_files = glob.glob(glob_pattern)
    glob_pattern = os.path.join(monitor_directory, '*')
    root_dir_files = glob.glob(glob_pattern)
    all_files = sub_dir_files + root_dir_files

    files_to_archive = []
    for thisfile in all_files:
        if os.path.isfile(thisfile) and file_older_than(thisfile, days_back):
            files_to_archive.append(thisfile)
        else:
            print("nope: {}".format(thisfile))

    return files_to_archive

def file_older_than(filename, days_back):
    now = time.time()
    # 86400 is seconds in a day
    return os.stat(filename).st_mtime < now - days_back * 86400


def zip_encrypt_file(existing_filepath, zip_encrypted_filepath):
    '''

    :param existing_filepath:
    :param zip_encrypted_filepath:
    :return:
    '''
    with pyzipper.AESZipFile(existing_filepath, 'w', compression=pyzipper.ZIP_LZMA, encryption=pyzipper.WZ_AES) as zf:
        zf.pwd = b'infected'
        zf.writestr(zip_encrypted_filepath, "What ever you do, don't tell anyone!")

def get_sha1(file_content):
    sha1_hasher = hashlib.sha1()
    sha1_hasher.update(file_content)
    digest = sha1_hasher.hexdigest()
    return digest

def zip_encrypt_content(content, zip_encrypted_filepath):
    '''

    :param existing_filepath:
    :param zip_encrypted_filepath:
    :return:
    '''
    with pyzipper.AESZipFile(zip_encrypted_filepath, 'w', compression=pyzipper.ZIP_LZMA, encryption=pyzipper.WZ_AES) as zf:
        zf.pwd = b'infected'
        zf.writestr(os.path.basename(zip_encrypted_filepath).split('.')[0], content)

def zip_decrypt_file(existing_filepath, decrypted_filepath):
    '''

    :param existing_filepath:
    :param decrypted_filepath:
    :return:
    '''
    with pyzipper.AESZipFile(existing_filepath) as zf:
        zf.pwd = b'infected'
        my_secrets = zf.read(decrypted_filepath)

def gzip_decompress_file(existing_filepath, decompressed_filepath=None):
    with gzip.open(existing_filepath, 'rb') as f:
        file_content = f.read()
    if decompressed_filepath is None:
        return file_content

def archive_by_hash(all_files, archive_directory):
    successfully_archived = []

    for file_to_archive in all_files:
        if file_to_archive.endswith('.gz'):
            raw_file_content = gzip_decompress_file(file_to_archive, decompressed_filepath=None)
            digest = get_sha1(raw_file_content)
            archive_filename = os.path.join(archive_directory, digest[0:3],'{}.ecr.zip'.format(digest))
            os.makedirs(os.path.join(archive_directory, digest[0:3]), exist_ok=True)
            zip_encrypt_content(raw_file_content, archive_filename)

    return successfully_archived

def archive_by_date(all_files, archive_directory):
    successfully_archived = []


    return successfully_archived

def remove_completed(successfully_archived):
    # Delete these files that have been successfully archived.

    return

def main(monitor_directory, days_back, archive_directory, archive_type, remove_in_place):
    successfully_archived = []

    # Input Validation
    days_back = validate_days_back(days_back)
    if not os.path.exists(monitor_directory):
        print("Monitor directory did not exist: {}".format(monitor_directory))
        exit()
    os.makedirs(archive_directory, exist_ok=True)

    # Get files
    all_files = get_files(monitor_directory, days_back)

    if archive_type == "hash":
        # zip individual
        successfully_archived = archive_by_hash(all_files, archive_directory)
    else:
        # save in directory by day, then zip that day's directory; good for logs
        successfully_archived = archive_by_date(all_files, archive_directory)

    if remove_in_place:
        remove_completed(successfully_archived)

    return 0

def validate_days_back(days_back):
    if days_back is None:
        print("days_back not supplied, defaulting to 7 days")
        return 7
    if days_back < 0:
        raise argparse.ArgumentTypeError("days_back must be a positive int value")
    return days_back

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Archive files in zip encrypted format to get around potential anti-virus complications.")
    parser.add_argument('-m', '--monitor_directory', help='Path to directory with files to monitor', required=True)
    parser.add_argument('-d', '--days_back', help='Number of days old the files must be before archiving them (defaults to 7)', type=int)
    parser.add_argument('-a', '--archive_dir', help='Directory to save archived data', required=True)
    parser.add_argument('-t', '--archive_type', help='Either "day" or "hash".  "day" organizes hashes in directories by date timestamps and zip encrypts the content.  "hash" uses the first 3 hex characters as the directory and zip encrypts content.', choices=['day', 'hash'], required=True)
    parser.add_argument('-r', '--remove_in_place', help='If successfully archived, then remove source files.', action='store_true')
    args = parser.parse_args()

    if not args.monitor_directory or not args.archive_dir or not args.archive_type:
        print("\nThe fields monitor_directory, archive_dir, and archive_type must be explicitly supplied.\n")
        parser.print_help()

    main(args.monitor_directory, args.days_back, args.archive_dir, args.archive_type, args.remove_in_place)
