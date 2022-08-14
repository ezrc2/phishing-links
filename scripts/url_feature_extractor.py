#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu May 14 13:23:31 2020

@author: hannousse
"""

import scripts.url_features as urlfe
#import ml_models as models
import pandas as pd 
import urllib.parse
import tldextract
import requests
import json
import csv
import os
import re


#from pandas2arff import pandas2arff
from urllib.parse import urlparse
from bs4 import BeautifulSoup

key = 'Add your OPR API key here'

import signal

class TimedOutExc(Exception):
    pass

def deadline(timeout, *args):
    def decorate(f):
        def handler(signum, frame):
            raise TimedOutExc()

        def new_f(*args):
            signal.signal(signal.SIGALRM, handler)
            signal.alarm(timeout)
            return f(*args)
            signal.alarm(0)

        new_f.__name__ = f.__name__
        return new_f
    return decorate

def get_domain(url):
    o = urllib.parse.urlsplit(url)
    return o.hostname, tldextract.extract(url).domain, o.path

 
    
    
#################################################################################################################################
#              Data Extraction Process
#################################################################################################################################


def extract_url_features(url):
    def words_raw_extraction(domain, subdomain, path):
        w_domain = re.split("\-|\.|\/|\?|\=|\@|\&|\%|\:|\_", domain.lower())
        w_subdomain = re.split("\-|\.|\/|\?|\=|\@|\&|\%|\:|\_", subdomain.lower())   
        w_path = re.split("\-|\.|\/|\?|\=|\@|\&|\%|\:|\_", path.lower())
        raw_words = w_domain + w_path + w_subdomain
        w_host = w_domain + w_subdomain
        raw_words = list(filter(None,raw_words))
        return raw_words, list(filter(None,w_host)), list(filter(None,w_path))
    
    hostname, domain, path = get_domain(url)
    extracted_domain = tldextract.extract(url)
    domain = extracted_domain.domain+'.'+extracted_domain.suffix
    subdomain = extracted_domain.subdomain
    tmp = url[url.find(extracted_domain.suffix):len(url)]
    pth = tmp.partition("/")
    path = pth[1] + pth[2]
    words_raw, words_raw_host, words_raw_path= words_raw_extraction(extracted_domain.domain, subdomain, pth[2])
    tld = extracted_domain.suffix
    parsed = urlparse(url)
    scheme = parsed.scheme

    row = [url,
           # url-based features
           urlfe.url_length(url),
           urlfe.url_length(hostname),
           urlfe.having_ip_address(url),
           urlfe.count_dots(url),
           urlfe.count_hyphens(url),
           urlfe.count_at(url),
           urlfe.count_exclamation(url),
           urlfe.count_and(url),
           urlfe.count_or(url),
           urlfe.count_equal(url),
           urlfe.count_underscore(url),
           urlfe.count_tilde(url),
           urlfe.count_percentage(url),
           urlfe.count_slash(url),
           urlfe.count_star(url),
           urlfe.count_colon(url),
           urlfe.count_comma(url),
           urlfe.count_semicolumn(url),
           urlfe.count_dollar(url),
           urlfe.count_space(url),

           urlfe.check_www(words_raw),
           urlfe.check_com(words_raw),
           urlfe.count_double_slash(url),
           urlfe.count_http_token(path),
           urlfe.https_token(scheme),

           urlfe.ratio_digits(url),
           urlfe.ratio_digits(hostname),
           urlfe.punycode(url),
           urlfe.port(url),
           urlfe.tld_in_path(tld, path),
           urlfe.tld_in_subdomain(tld, subdomain),
           urlfe.abnormal_subdomain(url),
           urlfe.count_subdomain(url),
           urlfe.prefix_suffix(url),
           urlfe.random_domain(domain),
           urlfe.shortening_service(url),


           urlfe.path_extension(path),
           urlfe.length_word_raw(words_raw),
           urlfe.char_repeat(words_raw),
           urlfe.shortest_word_length(words_raw),
           urlfe.shortest_word_length(words_raw_host),
           urlfe.shortest_word_length(words_raw_path),
           urlfe.longest_word_length(words_raw),
           urlfe.longest_word_length(words_raw_host),
           urlfe.longest_word_length(words_raw_path),
           urlfe.average_word_length(words_raw),
           urlfe.average_word_length(words_raw_host),
           urlfe.average_word_length(words_raw_path),

           urlfe.phish_hints(url),  
           urlfe.domain_in_brand(extracted_domain.domain),
           urlfe.brand_in_path(extracted_domain.domain,subdomain),
           urlfe.brand_in_path(extracted_domain.domain,path),
           urlfe.suspecious_tld(tld),
           urlfe.statistical_report(url, domain)]
    return row