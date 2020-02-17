import requests
import time
import argparse
import logging
import sys
import os
import json
import pandas as pd
import ntpath
import glob
import re
import datetime

# To get an API Key, go to www.hybrid-analysis.com and setup a free account, then login.
# In the upper right-hand corner, click on your user name > Profile.  Click on the API key tab and generate an API Key.
try:
    APIKEYS = os.environ['HYBRIDANALYSIS_API_KEY'].split(',')
    APIKEY_IDX = 0
except Exception as e:
    print("Error: You must set the environment variable HYBRIDANALYSIS_API_KEY to contain your key.")

def get_API_KEY():
    global APIKEY_IDX
    APIKEY_IDX = (APIKEY_IDX + 1) % len(APIKEYS)
    return APIKEYS[APIKEY_IDX]

def get_events(millis, retries=0):
    # global APIKEY

    url = 'https://www.hybrid-analysis.com/api/v2/feed/latest?_timestamp={}'.format(millis)
    header = {'api-key': get_API_KEY(),
              'user-agent': 'Falcon Sandbox'}
    r = requests.get(url, headers=header)

    if r.status_code != 200:
        logging.error('Error retrieving logs with status code {}'.format(r.status_code))
        logging.error("Critical error retrieving logs.  Exiting.")
        if retries < len(APIKEYS):
            return get_events(millis, retries + 1)
        else:
            logging.error('Giving up after {} retries.  Received status code: {}'.format(retries, r.status_code))
            sys.exit()

    samples = r.json()
    return samples

def download_sample(job_id, filename, type="bin", retries=0):
    url = 'https://www.hybrid-analysis.com/api/v2/report/{}/file/{}'.format(job_id, type)
    header = {'api-key': get_API_KEY(),
              'user-agent': 'Falcon Sandbox'}
    if not os.path.exists(filename):
        r = requests.get(url, headers=header)

        if r.status_code != 200:
            logging.error('Error retrieving {} with status code {}'.format(filename, r.status_code))
            if retries < len(APIKEYS):
                download_sample(job_id, filename, type, retries+1)
            else:
                logging.error('Giving up after {} retries.  Received status code: {}'.format(retries, r.status_code))
        else:
            with open(filename, 'wb') as f:
                f.write(r.content)

def download_dropped_files(job_id, filename, retries=0):
    url = 'https://www.hybrid-analysis.com/api/v2/report/{}/dropped-files'.format(job_id)
    header = {'api-key': get_API_KEY(),
              'user-agent': 'Falcon Sandbox'}
    if not os.path.exists(filename):
        r = requests.get(url, headers=header)

        if r.status_code != 200:
            logging.error('Error retrieving {} with status code {}'.format(filename, r.status_code))
            if retries < len(APIKEYS):
                download_dropped_files(job_id, filename, retries+1)
            else:
                logging.error('Giving up after {} retries.  Received status code: {}'.format(retries, r.status_code))
        else:
            with open(filename, 'wb') as f:
                f.write(r.content)

def get_most_recent(raw_dir):
    """
    Returns the filename with the largest timestamp.
    :param raw_dir: directory of raw logs (ending in .json)
    :return: filename
    """
    most_recent = ''
    try:
        files = glob.glob(os.path.join(raw_dir, '*.json'))
        largest = 0
        most_recent = ''
        for somefile in files:
            m = re.search('.*?([0-9]{13,14})_raw_ha_events.json', somefile)
            if m:
                found = m.group(1)
                if int(found) > largest:
                    largest = int(found)
                    most_recent = somefile
    except Exception as e:
        logging.error(e)

    return most_recent


def get_largest_timestamp(filename):
    """
    Loads raw log file and returns timestamp of event with most recent timestamp.
    :return: timestamp
    """
    try:
        df = pd.read_json(filename)
        df2 = df['data'].apply(pd.Series)
        df2['analysis_start_time_new'] = pd.to_datetime(df2['analysis_start_time'], format='%Y-%m-%d %H:%M:%S')
        timestamp = df2['analysis_start_time_new'].max()
    except:
        timestamp = pd.Timestamp(0)
        logging.warning(e)

    return timestamp


def write_raw_events(filename, samples):
    with open(filename, 'w') as fp:
        json.dump(samples, fp)

def save_proc_exec_events(filename, samples, fileformat='csv'):
    """
    type is 'csv' or 'json'
    :param filename:
    :param samples:
    :param type:
    :return:
    """
    proc_exec_events = []
    data = samples.get('data', [])

    for sample in data:
        # This section is really ugly because it looks like some field names changed slightly when the API was
        # updated to the next major version, so need to account for both field names
        threat_score = sample.get('threat_score', -1)
        threat_score = sample.get('threatscore', threat_score)

        submit_name = sample.get('submit_name', '')
        submit_name = sample.get('submitname', submit_name )

        threat_level = sample.get('threat_level', '')
        threat_level = sample.get('threatlevel', threat_level)

        size = sample.get('size', -1)

        threat_level_human = sample.get('threat_level_human', '')
        threat_level_human = sample.get('threatlevel_human', threat_level_human)

        sha1 = sample.get('sha1', '')

        vt_detect = sample.get('vt_detect', -1)

        processes = sample.get('processes', [])
        processes = sample.get('process_list', processes)

        timestamp = sample.get('analysis_start_time', '')

        url_analysis = sample.get('url_analysis', False)
        url_analysis = sample.get('isurlanalysis', url_analysis)

        type = sample.get('type', '')
        av_detect = sample.get('av_detect', -1)
        av_detect = sample.get(av_detect, -1)

        for process in processes:
            name = process.get('name', '')
            pid  = process.get('uid', '')
            ppid = process.get('parentuid', '')

            command_line = process.get('command_line', '')
            command_line = process.get('commandline', command_line)

            path = process.get('normalized_path', '')
            path = process.get('normalizedpath', path)

            path = path.replace(name, '')
            ms_detect = process.get('ms_detect', -1)

            entry = {'threat_score' : threat_score,
                     'submit_name' : submit_name,
                     'threat_level' : threat_level,
                     'size' : size,
                     'threat_level_human' : threat_level_human,
                     'url_analysis' : url_analysis,
                     'type' : type,
                     'av_detect' : av_detect,
                     'sha1' : sha1,
                     'vt_detect' : vt_detect,
                     'ms_detect' : ms_detect,
                     'timestamp' : timestamp,
                     'name' :name,
                     'pid' : pid,
                     'ppid' : ppid,
                     'command_line' : command_line,
                     'path' : path
                     }

            proc_exec_events.append(entry)

    if len(proc_exec_events) > 0:
        df = pd.DataFrame(proc_exec_events)
        df.fillna('')
        if fileformat == 'csv':
            filename = filename.replace('.json', '.csv')
            # Without adding the escape character, the command line arguments field will not always be formatted correctly
            df.to_csv(filename, index=False, header=True, encoding='utf-8', escapechar='\\')
        else:
            list_results = df.to_dict(orient='records')
            with open(filename, 'w') as f:
                for result in list_results:
                    f.write(json.dumps(result))
                    f.write('\n')
            filename.replace('.csv', '.json')
            # This would output as a single json file
            # df.to_json(filename, orient='records')


def get_recent_events(events, raw_dir):
    recent_file = get_most_recent(raw_dir)
    if recent_file == '':
        return events
    recent_timestamp = get_largest_timestamp(recent_file)
    samples = []

    for event in events['data']:
        event_timestamp = pd.Timestamp(datetime.datetime.strptime(event.get('analysis_start_time', '1970-01-01 01:01:01'), '%Y-%m-%d %H:%M:%S'))
        if event_timestamp > recent_timestamp:
            samples.append(event)

    return {'data' : samples}

def identify_and_download_samples(events, files_directory):
    records = events.get('data', [])

    for record in records:
        if record.get('shared_analysis', False) == True:
            if record.get('url_analysis', True) == False:
                subdir = ''
                filetype = record.get('type', '').lower()
                if 'ms windows shortcut' in filetype:
                    subdir = 'ms_win_shortcut'
                elif 'ms windows registry' in filetype:
                    subdir = 'ms_win_registry'
                elif 'htmlhelp' in filetype:
                    subdir = 'htmlhelp'
                elif 'microsoft' in filetype:
                    subdir = 'microsoft'
                elif 'pdf' in filetype:
                    subdir = 'pdf'
                elif 'rich text' in filetype:
                    subdir = 'rtf'
                elif 'text' in filetype:
                    subdir = 'text'
                elif 'java' in filetype:
                    subdir = 'java'
                else:
                    subdir = 'other'
                if subdir != '':
                    sub_directory = os.path.join(files_directory, subdir)
                    # If the directory doesn't exist, let's create it
                    if not os.path.exists(sub_directory):
                        os.makedirs(sub_directory)
                    job_id = record.get('job_id')
                    sha1 = record.get('sha1')
                    filename = '{}.gz'.format(sha1)
                    filename = os.path.join(sub_directory,filename)
                    download_sample(job_id, filename, type="bin")


def load_file(filename):
    # Handle both formats
    try:
        with open(filename) as f:
            data = json.load(f)
        return data
    except:
        data = []
        with open(filename) as f:
            for line in f:
                data.append(json.loads(line))
    return {'data' : data}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Pull events from Hybrid Analysis public feed every hour.")
    parser.add_argument('-r', '--raw_directory', help='Path to directory to save raw logs (defaults to current directory)')
    parser.add_argument('-p', '--parsed_directory', help='Path to directory to save process event logs only (defaults to current directory)')
    parser.add_argument('-l', '--log_directory', help='Path to log file directory (default is current directory)')
    parser.add_argument('-f', '--file_directory', help='Path to directory where malware samples will be downloaded (will not download malware if this is not specified)')
    parser.add_argument('-s', '--process_stored', help='Process stored raw logs in a directory')
    args = parser.parse_args()

    raw_dir = './'
    if args.raw_directory:
        raw_dir = args.raw_directory

    parsed_dir = './'
    if args.parsed_directory:
        parsed_dir = args.parsed_directory

    log_dir = './'
    if args.log_directory:
        log_dir = args.log_directory
    logging.basicConfig(filename=os.path.join(log_dir, 'get_ha_events.log'), level=logging.DEBUG, format='%(asctime)s %(message)s')

    if args.process_stored:
        if not args.parsed_directory:
            print('\nYou must supply a directory to write parsed files.\n')
            exit()
        files = glob.glob(os.path.join(args.process_stored, '*.json'))
        for filename in files:
            try:
                data = load_file(filename)
                saved_filename = os.path.basename(filename)
                saved_filename = saved_filename.replace('.json', '_processed.json')
                saved_filename = os.path.join(args.parsed_directory, saved_filename)
                save_proc_exec_events(saved_filename, data, fileformat='csv')
                if args.file_directory:
                    identify_and_download_samples(data, args.file_directory)
            except:
                print("Error processing {} ... skipping it".format(filename))

    else:
        # GET HA Events
        millis = str(int(round(time.time() * 1000)))
        try:
            events = get_events(millis)
            # Figure out what the last event is that we saw and return new events only.
            try:
                events = get_recent_events(events, raw_dir)
            except Exception as e:
                logging.error('Error deduping old events: {}'.format(str(e)))
        except Exception as e:
            logging.error(str(e))
            logging.error("Critical error.  Exiting.")
            sys.exit()

        # Write Raw Events
        raw_log_filename = os.path.join(raw_dir, '{}_raw_ha_events.json'.format(millis))
        write_raw_events(raw_log_filename, events)
        logging.debug("Finished writing raw events to disk.")

        # Save just process execution events
        proc_exec_log_filename = os.path.join(parsed_dir, '{}_proc_exec_ha_events.csv'.format(millis))
        save_proc_exec_events(proc_exec_log_filename, events)
        logging.debug("Finished writing parsed events to disk.")

        if args.file_directory:
            identify_and_download_samples(events, args.file_directory)
