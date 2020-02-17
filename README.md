# hybridanalysis_retrieval

Personal code used to retrieve hybrid analysis samples and parse metadata. 

### Setup
You need a hybrid analysis API key by registering and completing the vetting process.  Once you have that, set this environment variable to contain your key:

HYBRIDANALYSIS_API_KEY

### Usage
```
usage: get_ha_logs.py [-h] [-r RAW_DIRECTORY] [-p PARSED_DIRECTORY]
                      [-l LOG_DIRECTORY] [-f FILE_DIRECTORY]
                      [-s PROCESS_STORED]
Pull events from Hybrid Analysis public feed every hour.
optional arguments:
  -h, --help            show this help message and exit
  -r RAW_DIRECTORY, --raw_directory RAW_DIRECTORY
                        Path to directory to save raw logs (defaults to
                        current directory)
  -p PARSED_DIRECTORY, --parsed_directory PARSED_DIRECTORY
                        Path to directory to save process event logs only
                        (defaults to current directory)
  -l LOG_DIRECTORY, --log_directory LOG_DIRECTORY
                        Path to log file directory (default is current
                        directory)
  -f FILE_DIRECTORY, --file_directory FILE_DIRECTORY
                        Path to directory where malware samples will be
                        downloaded (will not download malware if this is not
                        specified)
  -s PROCESS_STORED, --process_stored PROCESS_STORED
                        Process stored raw logs in a directory
```


### Crontab example:
This cron job would run every hour to collect newly submitted malware samples
```
0 * * * *       /usr/bin/python3.6 <path_to_repo>/hybridanalysis_retrieval/get_ha_logs.py -r <path_to_raw_logs>/raw/ -p <path_to_parsed_logs>/parsed/ -l <path_to_log_dir>/hybrid_analysis/ -f <path_to_drop_samples>/samples
```
