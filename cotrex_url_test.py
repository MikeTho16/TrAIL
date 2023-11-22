#!/usr/bin/python3
""" Tests to make sure the URLs in the COTREX data work and lead to
meaningful pages.  In my experience I have found that they often do not.

Download COTREX and CPW trail data from:
https://data.colorado.gov/Recreation/Colorado-Trail-Explorer-COTREX-/tsn8-y22x
or
https://gisftp.colorado.gov/#/State%20Data/DNR/CPW/
* If necessary, convert to shapefile
* Rename to COTREX_Trails.shp
"""
import csv
import http.client
import math
import queue
import re
import socket
import ssl
import sys
import threading
import time
from urllib.parse import urlparse, urlunparse

from bs4 import BeautifulSoup
from osgeo import ogr

NUM_THREADS = 32
socket.setdefaulttimeout(10)

# Not sure we want to do the following.  Not so much of a security concern here,
# but some sites give a ssl.SSLCertVerificationError and then redirect
# pylint:disable=protected-access
ssl._create_default_https_context = ssl._create_unverified_context

def meta_redirect(content, cur_url):
    """ Constructs a new url from meta refresh tag.  If the meta refresh tag url
    is relative, make a absolute url using the current url (cur_url). If there is
    no meta tag with a refresh attribute, return None.

    Input(s):
        content - The content of the webpage that might contain a meta refesh tag
        cur_url - Current url

    Output(s):
        A new absolute URL if the content contains a meta tag with refresh attribute,
            otherwise None.
    """
    soup  = BeautifulSoup(content, 'html.parser')
    # URLs can be case sensitive, so we can't just lowercase the content and do
    # a compare (could be META or meta, or Meta). Instead we use regex to do a
    # case insensitive match.
    result = soup.find(re.compile('^meta$', flags=re.IGNORECASE),attrs={"http-equiv":"refresh"})
    if result:
        _,text = result["content"].split(";")
        if text.strip().lower().startswith("url="):
            url = text.strip()[4:]
            if not url.startswith('http'):
                parsed_url = urlparse(cur_url)
                url = urlunparse(parsed_url._replace(path=url))
            return url
    return None

def get_url(url, conn):
    """ Gets the specified URL and tests it to see if it works.  This method is
    called recursively if the URL redirects.

    Input(s):
        url - url which is to be tested.
        conn - The connection to use.  If None, create a new connection.

    Output(s):
        status - http status code
        data - The data/content returned by the URL
        message - Description of what went wrong
        success - True of there were no errors, False if there were
    """
    # We want to make it look like we are a regular browser, so set the headers
    # accordingly.
    my_headers = {
                  'accept': ('text/html,application/xhtml+xml,application/xml;q=0.9,'
                             'image/avif,image/webp,image/apng,*/*;q=0.8'),
                  'accept-language': 'en-US,en;q=0.8',
                  'cache-control': 'max-age=0',
                  'cookie': 'WSS_FullScreenMode=false',
                  'sec-ch-ua': '"Chromium";v="118", "Brave";v="118", "Not=A?Brand";v="99"',
                  'sec-ch-ua-mobile': '?0',
                  'sec-ch-ua-platform': '"Linux"',
                  'sec-fetch-dest': 'document',
                  'sec-fetch-mode': 'navigate',
                  'sec-fetch-site': 'cross-site',
                  'sec-fetch-user': '?1',
                  'sec-gpc': '1',
                  'upgrade-insecure-requests': '1',
                  'user-agent': ('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
                                 '(KHTML, like Gecko)Chrome/118.0.0.0 Safari/537.36')
                  }
    url = url.strip()
    parsed_url = urlparse(url)
    netloc = parsed_url.netloc
    path = urlunparse(parsed_url._replace(scheme='')._replace(netloc=''))
    try:
        if parsed_url.scheme.lower() == 'http':
            conn = http.client.HTTPConnection(netloc, timeout=30)
        else:
            conn = http.client.HTTPSConnection(netloc, timeout=30)
        conn.request("GET", path, headers=my_headers)
        response = conn.getresponse()
    except ConnectionRefusedError:
        if parsed_url.scheme.lower() == 'http':
            new_url = urlunparse(parsed_url._replace(scheme='https'))
            status, data1, msg, success = get_url(new_url, None)
        else:
            status = None
            data1 = None
            msg = 'ConnectionRefusedError'
            success = False
    except Exception as inst:
        status = None
        data1 = None
        msg = repr(inst)
        success = False
    else:
        status = response.status
        # 301 is a redirect, try to follow it, it may be valid
        # 302 is a temporary redirection, also try to follow it
        if status in (301, 302):
            new_url = response.getheader('Location')
            if new_url is not None:
                if not new_url.lower().startswith('http'):
                    parsed_url = urlparse(url)
                    new_url = urlunparse(parsed_url._replace(path=new_url))
                status, data1, msg, success =  get_url(new_url, None)
            else:
                data1 = response.read()
                msg = 'Redirect without Location header'
                success = False
        elif status == 200:
            data1 = response.read()
            # Check for meta redirect.  A webpage can redirect by having
            # <META http-equiv="refresh" content="0;URL=/
            new_url = meta_redirect(data1, url)
            if new_url is not None:
                status, data1, msg, success =  get_url(new_url, None)
            elif b'NOT FOUND' in data1.upper():
                msg = 'Not Found'
                success = False
            elif b'INVALIDURL' in data1.upper() or b'INVALID URL' in data1.upper():
                msg = 'Invalid URL'
                success = False
            elif b'NO RESULTS FOUND' in data1.upper():
                msg = 'No Results Found'
                success = False
            elif b'SOMETHING WENT WRONG' in data1.upper():
                msg = 'Something Went Wrong'
                success = False
            else:
                msg = 'OK'
                success = True
        else:
            data1 = None
            msg = response.reason
            success = False
    finally:
        conn.close()
    return status, data1, msg, success

def test_url(queue_in, queue_out):
    """ Tests urls.  Meant to be run as a separate thread. Reads from queue_in,
    tests the URL thus obtained, and if there is a failure, put a message in
    queue_out.  Continues reading from queue_in until a "done" token is
    encountered, at which point it exits.

    Input(s):
        queue_in - Queue of URLs to test.
        queue_out - Queue into which to put errors.  These are handled by
            separate process.

    """
    print('starting test thread')
    done = False
    while not done:
        message = queue_in.get()
        done = message[4]
        if not done:
            url = message[0]
            _, _, msg, success = get_url(url, None)
            if not success:
                message.append(msg)
                queue_out.put(message)
    print('ending test thread')

def write_results(queue_out, lock):
    """ Writes results from URL test to disk.  Meant to be run as separate thread.
    Reads from queue_out and writes the result to disk.  Continues to do this
    until a "done" token is encountered in queue_out, at which point the thread
    exits.

    Input(s):
        queue_out - Queue containing information about URL test failures.
        lock - Used to prevent other thread from interupting this thread
            at critical times.  Probably not needed.
    Output(s):
        <nothing>
    """
    print('starting write thread')
    error_log_file = open('./cotrex_url_errors2.csv', 'w', newline='', encoding='utf-8')
    fieldnames = ['feature_id', 'manager','name', 'url', 'error_message']
    writer = csv.DictWriter(error_log_file, fieldnames=fieldnames)
    writer.writeheader()
    done = False
    while not done:
        message = queue_out.get(block=True, timeout=None)
        done = message[4]
        if not done:
            lock.acquire()
            writer.writerow({'feature_id': message[1], 'manager': message[3], 'name': message[1],
                             'url': message[0], 'error_message': message[5]})
            lock.release()
    error_log_file.close()
    print('ending write thread')

def read_feature(cotrex_feature, lock):
    """ Reads information about the COTREX feature.

    Input(s):
        cotrex_feature - COTREX feature which is to be read.
        lock - Python threading lock.  This is used to ensure that read operations
            are 'atomic' and cannot be interrupted.  It is not certain that this
            is actually needed.

    Output(s):
        url - The URL associated with cotrex_feature.
        manager - The manager of the cotrex_feature (trail).
        name - The name of the cotrex_feature (trail).
        feature_id - The feature_id of the cotrex_feature (trail).
    """
    lock.acquire()
    url = cotrex_feature.GetField('url')
    if url is None:
        url = ''
    manager = cotrex_feature.GetField('manager')
    if manager is None:
        manager = ''
    name = cotrex_feature.GetField('name')
    if name is None:
        name = ''
    feature_id = cotrex_feature.GetField('feature_id')
    if feature_id is None:
        feature_id = ''
    lock.release()
    return url, manager, name, feature_id

def main():
    """ Main function of program.
    """
    start = time.time()

    # COTREX Trails
    # TODO - read the name of the COTREX file from the command line
    cotrex_fname = './COTREX_Trails.shp'
    driver = ogr.GetDriverByName("ESRI Shapefile")
    data_source = driver.Open(cotrex_fname, 0)
    cotrex_layer = data_source.GetLayer()
    cotrex_feature_count =  cotrex_layer.GetFeatureCount()
    # TODO - These counts are not correct as we are now only testing
    # unique URLs
    count = 0
    percent = -1
    total_trails = 0
    trails_w_no_url = 0
    trails_w_invalid_url = 0
    # sometimes multiple trails have the same url, keep track of them so
    # we don't waste time testing them again
    urls = {}
    queue_in = queue.Queue(maxsize=NUM_THREADS*4)
    queue_out = queue.Queue(maxsize=NUM_THREADS*4)
    lock = threading.Lock()
    threads = []
    # Make threads for testing the URLs
    for _ in range(NUM_THREADS):
        testing_thread = threading.Thread(target=test_url, args=(queue_in, queue_out))
        threads.append(testing_thread)
        testing_thread.start()
    # Make thread for writing results
    write_thread = threading.Thread(target=write_results, args=(queue_out, lock))
    write_thread.start()
    for cotrex_feature in cotrex_layer:
        count += 1
        url, manager, name, feature_id = read_feature(cotrex_feature, lock)
        total_trails += 1
        # TESTING
        #if count > 3000:
        #    break
        # END TESTING
        # Display percent progress
        if math.floor((count / cotrex_feature_count) * 100) > percent:
            percent = math.floor((count / cotrex_feature_count) * 100)
            sys.stdout.write(f'Testing trail URLs: {percent}%\r')
            sys.stdout.flush()
        # End - Display percent progress
        # Bypass URLs that are blank or NULL
        url = cotrex_feature.GetField('url')
        if url is None or url.upper() == 'NULL' or url == '':
            trails_w_no_url += 1
            continue
        message = [url, feature_id, name, manager, False]
        if url in urls:
            continue
        urls[url] = True
        queue_in.put(message)
    print('all data in                         ')
    # Let the threads know that all of the data has been put into the input queue
    for _ in range(NUM_THREADS):
        queue_in.put([None,None,None,None,True])
    # Wait for all of the threads to finish
    for thread in threads:
        thread.join()
    queue_out.put([None,None,None,None,True])
    write_thread.join()
    end = time.time()
    print('                                             ')
    print(f'Total trails: {total_trails}')
    print(f'Trails w/ no URL: {trails_w_no_url}')
    print(f'Trails w/ invalid URL: {trails_w_invalid_url}')
    print(f'Trails w/ valid URL: {total_trails - trails_w_no_url - trails_w_invalid_url}')
    print(f'Overall runtime: {end - start}')

if __name__ == '__main__':
    main()
