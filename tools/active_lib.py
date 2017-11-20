# -*- coding: utf-8 -*-
#Castro Rendón Virgilio
import urllib3
from requests import get
from anytree import Node, RenderTree, Resolver, DoubleStyle, PreOrderIter
from django.core.files import File
from re import search
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
debug = True

"""
Return an URL depending on the user configuration.
This function is important to look for this URL in the HTTP response and crawl it.
"""
def get_url(url):
    if url.endswith('/'):
        url = url[:-1]
    if not (url.startswith('http://') or url.startswith('https://')):
        url = 'http://'+url
    site = url.split('//')[1]
    if '/' in site:
        site = site.split('/')[0]
    return site, url


"""
This is a recursive function that add to the "base" node all the data in "resource"
"Resource" is a list of the components of an URL (splitted by '/')
"""
def add_to_structure(base, resource):
    try:
        r = Resolver("name")
        try:
            if '?' in resource[0]:
                return
            existing_node = r.get(base, resource[0])
            if len(resource) > 1:
                add_to_structure(existing_node,resource[1:])
        except Exception as e:
            new_node = Node(resource[0],parent=base)
            if len(resource) > 1:
                add_to_structure(new_node,resource[1:])
    except Exception as e:
        return {'web_structure':e}


"""
Returns a string that can be printed in a "text area" in form of a tree.
"""
def render_tree(root):
    result = ''
    for pre, _, node in RenderTree(root,style=DoubleStyle):
        result += ('%s%s' % (pre, node.name))
        result += '\n'
    return result


"""
Looks in the HTTP response all the coincidences of the URL of the site.
Initially, it looks for strings in the form of: "http(s)://mysite.com so
it can be crawled. When the resource is found, adds it to the structure (tree)
"""
def get_tree_href(text,site,url):
    base_node = Node(site, parent=None)
    base = '\"'+url #The base is something like: "http://mysite.com
    for line in text: 
        #Looks for the index of all the substrings that start with the base one in a single line
	indexes = [i for i in range(len(line)) if line.startswith(base, i)]
        if indexes != []:
	    for index in indexes:
	        f_char_index = index + 1    #The first char of the url removes the '"' char added in the base substring
	        #The last char of the url is '"'. The first index is added to get the index in the whole file
	        l_char_index = line[f_char_index:].index('"') + f_char_index  
	        url = line[f_char_index:l_char_index]
	        resource = url.split('//')[1].split('/')[1:]
	        add_to_structure(base_node,resource)
    return base_node


"""
This function is similar to "get_tree_href" but it looks for links that are called with "href" and "src"
but does not start with "http" or "//" so links that are made "locally" can be added by the crawler
"""
def update_tree_src(tree, text):
    base1 = 'src="' 
    base2 = 'href="'
    for line in text: 
	indexes1 = [i for i in range(len(line)) if line.startswith(base1, i)]
	indexes2 = [i for i in range(len(line)) if line.startswith(base2, i)]
        if indexes1 != []:
	    for index in indexes1:
	        f_char_index = index + 5    
	        l_char_index = line[f_char_index:].index('"') + f_char_index  
	        url = line[f_char_index:l_char_index].strip()
                if not url.startswith('http') and not url.startswith('//'):
                    resource = url.split('/')
        	    add_to_structure(tree,resource)
        if indexes2 != []:
	    for index in indexes2:
	        f_char_index = index + 6    
	        l_char_index = line[f_char_index:].index('"') + f_char_index  
	        url = line[f_char_index:l_char_index].strip()
                if not url.startswith('http') and not url.startswith('//'):
        	    resource = url.split('/')
        	    add_to_structure(tree,resource)


"""
Makes the HTTP get request and calls the other functions to make the crawling
"""
def map_server(site, url):
    try:
        response = get(url, verify=False, timeout=5)
        if debug: print '\n\n\n%s\n%s\n%s' % ('*'*30,'Server map', '*'*30)
        if debug: print '\n'+url
        if response.status_code == 200:
            text = response.text.split('\n')
            tree = get_tree_href(text, site, url)
            update_tree_src(tree, text)
            rendered_tree = render_tree(tree)
            return {'web_structure':rendered_tree},tree
        else:
            raise ValueError('Did not receive a valid response from server')
    except Exception as e:
        return {'error1': e}


"""
It is used to get a path like "/img/2017/nov" from the tree structure.
This path will be used to complete the URLs and look for important files
"""
def get_node_path(node):
    try:
        path = '/'
        for n in node.path[1:]:
            path += ('%s/' % n.name)
        return path
    except Exception as e:
        pass


"""
This function looks for all the nodes in the tree that are not leafs. This is useful to determine
which of the nodes are directories and which are files. It may be that some leaf nodes are also
directories but the tool will suppose the opposite
"""
def get_directories(url, tree):
    try:
        a = []
        directory_nodes = [node for node in PreOrderIter(tree, filter_=lambda n: not n.is_leaf or n.is_root)]
        for n in directory_nodes:
            dir_url = '%s%s' % (url,get_node_path(n))
            a.append(dir_url)
        return a
    except Exception as e:
        pass 


"""
Will look in all the directories for some common names that may represent backup files.
This function is as fast or slow as the amount of directories found.
"""
def get_backup_files(url):
    try:
        backups_result = []
        if debug: print '\n\n\n%s\n%s\n%s' % ('*'*30,'Backup files', '*'*30)
        with open('/opt/backup_names.short','r') as f:
            files = File(f)
            for _file in files:
                new_url = ('%s/%s' % (url,_file[:-1]))
                if debug: print '\n'+new_url
                response = get(new_url, verify=False, timeout=4)
                if debug: print 'Code: %s\tRedirects history: %s' % (response.status_code, response.history)
                if response.status_code == 200:
                    for h in response.history:
                        if h.status_code == 302:
                            break
                    else:
                        backups_result.append(new_url)
        result_dict = {'backups':backups_result} if backups_result != [] else {'backups':"False"}
        return result_dict
    except Exception as e:
        result_dict = {'backups':backups_result} if backups_result != [] else {'backups':"False"}
        #result_dict.update({'error2':[e]})
        print e
        return result_dict


"""
Will look in all the directories for some common names that may represent sensitive files.
This function is as fast or slow as the amount of directories found.
"""
def get_sensitive_files(url):
    try:
        result = []
        if debug: print '\n\n\n%s\n%s\n%s' % ('*'*30,'Sensitive files', '*'*30)
        with open('/opt/sensitive_files.short','r') as f:
            files = File(f)
            for _file in files:
                new_url = ('%s/%s' % (url,_file[:-1]))
                if debug: print '\n'+new_url
                response = get(new_url, verify=False, timeout=4)
                if debug: print 'Code: %s\tRedirects history: %s' % (response.status_code, response.history)
                if response.status_code == 200:
                    for h in response.history:
                        if h.status_code == 302:
                            break
                    else:
                        result.append(new_url)
        result_dict = {'sensitive_files':result} if result != [] else {'sensitive_files':"False"}
        return result_dict
    except Exception as e:
        result_dict = {'sensitive_files':result} if result != [] else {'sensitive_files':"False"}
        #result_dict.update({'error3':[e]})
        print e
        return result_dict


"""
This function will make a request for each directory found. It tries to determine of that directory allows indexing/listing.
"""
def get_directory_indexing(urls):
    try:
        result = []
        if debug: print '\n\n\n%s\n%s\n%s' % ('*'*30,'Directory indexing', '*'*30)
        for u in urls:
            if debug: print '\n'+u
            response = get(u, verify=False, timeout=4, allow_redirects=False)
            if debug: print response.status_code
            if not (response.status_code in [200] and ('Index of' in response.text or 'Directory listing for' in response.text)):
                continue
            else:
                result.append(u)
        result_dict = {'indexing':result} if result != [] else {'indexing':"False"}
        return result_dict
    except Exception as e:
        result_dict = {'indexing':result} if result != [] else {'indexing':"False"}
        #result_dict.update({'error4':[e]})
        print e
        return result_dict


"""
Will look in all the directories for some common names that may represent installation directories.
This function is as fast or slow as the amount of directories found.
"""
def get_installation_dirs(url):
    try:
        result = []
        if debug: print '\n\n\n%s\n%s\n%s' % ('*'*30,'Installation Directories', '*'*30)
        with open('/opt/installation_dirs','r') as f:
            files = File(f)
            for _file in files:
                new_url = ('%s/%s' % (url,_file[:-1]))
                if debug: print '\n'+new_url
                response = get(new_url, verify=False, timeout=4)
                if debug: print 'Code: %s\tRedirects history: %s' % (response.status_code, response.history)
                if response.status_code == 200:
                    for h in response.history:
                        if h.status_code == 302:
                            break
                    else:
                        result.append(new_url)
        result_dict = {'installation_dirs':result} if result != [] else {'installation_dirs':"False"}
        return result_dict
    except Exception as e:
        result_dict = {'installation_dirs':result} if result != [] else {'installation_dirs':"False"}
        #result_dict.update({'error5':[e]})
        print e
        return result_dict


"""
Will look in all the directories for some common names that may represent administration pages.
This function is as fast or slow as the amount of directories found.
"""
def get_admin_dirs(url):
    try:
        result = []
        if debug: print '\n\n\n%s\n%s\n%s' % ('*'*30,'Administration directories', '*'*30)
        with open('/opt/admin_dirs.short','r') as f:
            files = File(f)
            for _file in files:
                new_url = ('%s/%s' % (url,_file[:-1]))
                if debug: print '\n'+new_url
                response = get(new_url, verify=False, timeout=4)
                if debug: print 'Code: %s\tRedirects history: %s' % (response.status_code, response.history)
                if response.status_code == 200:
                    for h in response.history:
                        if h.status_code == 302:
                            break
                    else:
                        result.append(new_url)
        result_dict = {'admin_dirs':result} if result != [] else {'admin_dirs':"False"}
        return result_dict
    except Exception as e:
        result_dict = {'admin_dirs':result} if result != [] else {'admin_dirs':"False"}
        #result_dict.update({'error6':[e]})
        print e
        return result_dict


def get_cms(url):
    try:
        result = ''
        if debug: print '\n\n\n%s\n%s\n%s' % ('*'*30,'CMS detection', '*'*30)
        if debug: print '\n'+url
        response = get(url, verify=False, timeout=4)
        if debug: print 'Code: %s\tRedirects history: %s' % (response.status_code, response.history)
        
        regex_generator = r'<meta name="generator" content="(?P<generator>[^"]+)"'
        regex_moodle = r'<meta name="keywords" content="moodle'
        generator = search(regex_generator,response.text)
        moodle = search(regex_moodle,response.text)

        if generator is not None:
            result = generator.group('generator')
        elif moodle is not None:
            result = 'Moodle'
        
        result_dict = {'cms':result} if result != '' else {'cms':'Could not determine the CMS.'}
        return result_dict
    except Exception as e:
        result_dict = {'cms':result} if result != '' else {'cms':'Could not determine the CMS.'}
        #result_dict.update({'error7':[e]})
        print e
        return result_dict


"""
Calls the other functions tog get info from the server
"""
def active_analysis(url):
    site, url = get_url(url)
    result_dict = {'result':True, 'active_url':url}
    try:
        if url == '':
            return {'active_url':'Specify the URL to analyze.'}
        web_structure, tree = map_server(site,url)
        dirs = get_directories(url, tree)
        result_dict.update(web_structure)
        result_dict.update(get_backup_files(url))
        result_dict.update(get_sensitive_files(url))
        result_dict.update(get_directory_indexing(dirs))
        result_dict.update(get_installation_dirs(url))
        result_dict.update(get_admin_dirs(url))
        result_dict.update(get_cms(url))
        return result_dict
    except ValueError as e:
        print e
        result_dict.update({'error1':'Maybe the server is not up', 'result':True})
        return result_dict
