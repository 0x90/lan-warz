#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# Dummy HTTP scan script

from argparse import ArgumentParser, RawDescriptionHelpFormatter
from Queue import Queue
from signal import signal, SIGINT
from os import path
from datetime import datetime
from time import sleep
from threading import Thread
import logging

# http://stackoverflow.com/questions/12601316/how-to-make-python-requests-work-via-socks-proxy
from requesocks import get
# from requests import get

class HTTPScanThread(Thread):

    def __init__(self, host, urls, proxy=None):
        Thread.__init__(self, )
        self.host = host
        self.urls = urls
        if proxy is not None:
            self.proxies = {'http': proxy, 'https': proxy}
        else:
            self.proxies = None

        self.daemon = True
        self._stop = False

    def stop(self):
        logging.debug('Stopping thread: %s..' % self.name)
        self._stop = True

    def run(self):
        logging.debug('Starting thread: %s..' % self.name)
        while True:
            try:
                url = self.urls.get(False)
                if url is None:
                    break
            except:
                break

            full_url = 'http://%s/%s' % (self.host, url)
            print('Checking: %s' % full_url)

            if self.proxies is None:
                r = get(full_url)
            else:
                r = get(full_url, proxies=self.proxies)

            if r.status_code == 200:
                print('[+] Valid url found : %s' % full_url)
            else:
                logging.debug('[-] %s => %i' % (full_url, r.status_code))

            self.urls.task_done()


class HTTPScan(object):

    def __init__(self, host, urls_file, proxy=None, threads=5):
        self.host = host
        self.urls = Queue()
        if not path.exists(urls_file):
            logging.error('urls file not found')
            exit(-1)

        for url in filter(lambda x: len(x) > 0, open(urls_file, 'rb').read().split("\n")):
            self.urls.put(url)
        # Create a thread pool and give them a queue
        self.threads = [HTTPScanThread(self.host, self.urls) for i in range(threads)]
        self._stop = False

    def run(self):
        print('Loaded  %i urls.' % (self.urls.qsize()))
        logging.debug('Setting signal handler...')
        signal(SIGINT, self.signal_handler)

        print('Starting threads...')
        map(lambda t: t.start(), self.threads)

        # Wait for threads to finish
        # self.threads[0].join()
        while True:
            if not any([thread.isAlive() for thread in self.threads]):
                print('All threads have stopped')
                break
            # TODO: add progress here
            sleep(1)

    def signal_handler(self, signal, frame):
        print('You pressed Ctrl+C! Exiting...')
        for t in self.threads:
            t.stop()


def main():
    parser = ArgumentParser(prog='httpscan', description="Dummy HTTP scanner", formatter_class=RawDescriptionHelpFormatter)
    parser.add_argument('host', help='host 4 http scan')
    parser.add_argument('urls', help='file with urls to check')
    parser.add_argument('-t', '--threads', type=int, default=1, help='thread count')
    parser.add_argument('-p', '--proxy', required=False, help='proxy param example: socks5://127.0.0.1:9050')
    # parser.add_argument('-o', '--output', default='valid.txt', help='output to save valid accounts')
    parser.add_argument('-d', '--debug', action='store_true', help='enable debug output')
    parser.add_argument('--version', action='version', version='%(prog)s 0.1')
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    start_time = datetime.now()
    HTTPScan(args.host, args.urls, args.threads).run()
    print("Start time: " + start_time.strftime('%Y-%m-%d %H:%M:%S'))
    print("Finish time: " + datetime.now().strftime('%Y-%m-%d %H:%M:%S'))


if __name__ == '__main__':
    main()
