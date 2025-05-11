'''
Date: 2025-05-11 09:54:36
LastEditors: LevinKai
LastEditTime: 2025-05-11 12:17:25
FilePath: \\Work\\MovieLibrary\\url_content.py
'''
import json
import requests
from bs4 import BeautifulSoup

def get_url_content(url='',method = 'get'):
    print(f'get_url_content url:{url} method:{method}')
    if not url:
        print('invalid url!')
        return ''
    
    try:
        if 'get' == method:
            # request.get full headers
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Connection": "keep-alive",
                "Referer": "https://google.com",
            }
            response = requests.get(url, headers=headers)
            #print(response.text)
            return response.text
        elif 'session' == method:
            #session
            session = requests.Session()
            session.headers.update({
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            })
            response = session.get(url)
            #print(response.text)
            return response.text
            # js web
            # from selenium import webdriver
            # from selenium.webdriver.common.by import By

            # # 启动浏览器
            # driver = webdriver.Chrome()  # 确保已安装 ChromeDriver
            # driver.get("https://example.com")

            # # 获取网页内容
            # html = driver.page_source
            # print(html)

            # # 关闭浏览器
            # driver.quit()

            # auto browser
            # pip install playwright
            # playwright install

            # from playwright.sync_api import sync_playwright

            # with sync_playwright() as p:
            #     browser = p.chromium.launch(headless=True)
            #     page = browser.new_page()
            #     page.goto("https://example.com")
            #     content = page.content()
            #     print(content)
            #     browser.close()
    except Exception as e:
        print(f'get_url_content fail:{e}')
    
    return ''

def html_to_dict(element):
    """
    递归地将 HTML 元素及其子元素解析为嵌套字典。
    
    :param element: BeautifulSoup 的 Tag 对象或 NavigableString 对象
    :return: Python 字典或字符串
    """
    # 如果是 NavigableString（文本节点），直接返回其内容
    if element.name is None:
        return element.strip() if element.strip() else None  # 忽略空白文本

    # 创建一个字典来存储当前节点的信息
    node = {}

    # 保存当前标签的属性
    if element.attrs:
        node['attributes'] = element.attrs

    # 遍历子元素
    children = []
    for child in element.children:
        child_data = html_to_dict(child)
        if child_data is not None:  # 忽略空内容
            children.append(child_data)

    # 如果有子元素，添加到节点中
    if children:
        node['children'] = children

    # 保存标签名
    node['tag'] = element.name

    return node

def parse_html_to_dict(html_string):
    """
    将 HTML 字符串解析为嵌套字典结构。
    """
    soup = BeautifulSoup(html_string, 'html.parser')
    return html_to_dict(soup)

def parse_html_str(html_string='',keyword_start='',keyword_end=''):
    """
    解析 HTML 格式的字符串并提取关键信息。
    
    :param html_string: HTML 格式的字符串
    :return: 解析后的信息字典
    """
    data = ''
    try:
        ret = html_string.find(keyword_start)
        if -1 != ret:
            start = ret + len(keyword_start)
            ret = html_string.find(keyword_end,start)
            if -1 != ret:
                data = html_string[start:ret]
    except Exception as e:
        print(f'parse_html_str fail!{e}')
        
    return data

def search_douban_get_score(movie=''):
    print(f'search_douban_get_score {movie}')
    if not movie:
        print('invalid movie')
    url = f'https://search.douban.com/movie/subject_search?search_text={movie}'
    html = get_url_content(url,'get')
    data = parse_html_str(html,'window.__DATA__ = ',keyword_end=';\n')
    try:
        data = json.loads(data)
    except Exception as e:
        print(f'json dump fail:{e}')
        
    if isinstance(data,dict):
        items = data.get('items')
        if isinstance(items,list):
            print(f'movie:{movie}')
            for item in items:
                title = item.get('title')
                if movie not in title:
                    print(f'not this movie {title}')
                    continue
                rating = item.get('rating')
                cover_url = item.get('cover_url')
                url = item.get('url')
                print(f'{title}\n{rating}\n{cover_url}\n{url}')
    # print(data)
if __name__ == "__main__":
    search_douban_get_score('雷霆特攻队')