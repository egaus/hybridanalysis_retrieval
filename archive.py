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
    '''
    Returns all files in the provided directory and subdirectories.
    :param monitor_directory: directory to monitor
    :param days_back: number of days back to filter on (must be older than this number of days to be included)
    :return: list of files matching age requirement
    '''
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
    '''
    Given a file name, returns True or False if it was created more than the provided days_back
    :param filename: path to file
    :param days_back: number of days to check
    :return: True or False
    '''
    now = time.time()
    # 86400 is seconds in a day
    return os.stat(filename).st_mtime < now - days_back * 86400

def get_sha1(file_content):
    '''
    Computes the sha1 digest of the provided file content
    :param file_content: byte array of file content
    :return: sha1 digest as a string
    '''
    sha1_hasher = hashlib.sha1()
    sha1_hasher.update(file_content)
    digest = sha1_hasher.hexdigest()
    return digest

def zip_encrypt_content(content, zip_encrypted_filepath):
    '''
    Given the content of a file to write, zip encrypts it with the standard password 'infected'
    :param content: byte array with content to write to file
    :param zip_encrypted_filepath: absolute file path where to write encrypted file
    :return: None
    '''
    with pyzipper.AESZipFile(zip_encrypted_filepath, 'w', compression=pyzipper.ZIP_LZMA, encryption=pyzipper.WZ_AES) as zf:
        zf.pwd = b'infected'
        zf.writestr(os.path.basename(zip_encrypted_filepath).split('.')[0], content)

def zip_decrypt_file(existing_filepath):
    '''
    Decrypts encrypted file with the password 'infected'
    :param existing_filepath:
    :return: file_content
    '''
    with pyzipper.AESZipFile(existing_filepath) as zf:
        zf.pwd = b'infected'
        file_content = zf.read(os.path.basename(existing_filepath).split('.')[0])
    return file_content

def gzip_decompress_file(existing_filepath, decompressed_filepath=None):
    with gzip.open(existing_filepath, 'rb') as f:
        file_content = f.read()
    if decompressed_filepath is None:
        return file_content

def archive_by_hash(all_files, archive_directory):
    '''
    Archives the list of provided files, zip encrypting them with the standard password 'infected'.  Files saved
    in a directory named as the first three hex characters of their sha1 hash.  File names are the sha1 hash of their
    content.
    :param all_files: list of absolute file paths
    :param archive_directory: base directory to save files to.
    :return: files successfully archived without generating an exception or error
    '''
    successfully_archived = []

    for file_to_archive in all_files:
        try:
            if file_to_archive.endswith('.gz'):
                raw_file_content = gzip_decompress_file(file_to_archive, decompressed_filepath=None)
                digest = get_sha1(raw_file_content)
                archive_filename = os.path.join(archive_directory, digest[0:3],'{}.ecr.zip'.format(digest))
                os.makedirs(os.path.join(archive_directory, digest[0:3]), exist_ok=True)
                zip_encrypt_content(raw_file_content, archive_filename)
                successfully_archived.append(file_to_archive)
        except Exception as e:
            print("Failed to archive {}: {}".format(file_to_archive, e))

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
