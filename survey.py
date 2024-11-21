import requests
from urllib.parse import urlparse, urlunparse
from bs4 import BeautifulSoup
from collections import OrderedDict
import re

def is_valid_url(url):
    """
    Check if the url is valid.

    Parameters:
    url (str): The url to be checked.

    Returns:
    bool: True if valid, False otherwise.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

def get_links(url, tag_class=None):
    """
    returns a list of all valid linked urls with no paths or duplicates
    """
    # gets all the links on a site without duplicates
    req = requests.get(url)
    soup = BeautifulSoup(req.content, 'html.parser')
    if tag_class is not None:
        links = [ urlunparse(urlparse(link.get('href'))._replace(path='',query='',params='',fragment='')) for link in soup.find_all('a',class_=tag_class)]
    else:
        links = [ urlunparse(urlparse(link.get('href'))._replace(path='',query='',params='',fragment='')) for link in soup.find_all('a')]
    no_duplicates = list(OrderedDict.fromkeys(links))
    return [ link for link in no_duplicates if is_valid_url(link) ]

def survey():
    # Get the top 100 most visited sites
    list_url = "https://en.wikipedia.org/wiki/List_of_most-visited_websites"
    links = get_links(list_url, "external text")
    return links


def main():
    # List of URLs to check, this should be done automatically by fetching the top N most visited sites
    links = survey()
    print(len(links))

if __name__ == "__main__":
    main()
