# -*- coding: utf-8 -*-
#Castro Rendón Virgilio
from requests import get
from anytree import Node, RenderTree, Resolver, DoubleStyle, ContRoundStyle

def get_url(ip,port,protocol):
    if protocol == "HTTP":
        if port not in ['80','443']:
            url = "http://%s:%s" % (ip, port)
        else:
            url = "http://%s" % (ip)
    else:
        if port not in ['80','443']:
            url = "https://%s:%s" % (ip, port)
        else:
            url = "https://%s" % (ip)
    return url

def add_to_structure(base, resource):
    try:
        r = Resolver("name")
        try:
            existing_node = r.get(base, resource[0])
            if len(resource) > 1:
                add_to_structure(existing_node,resource[1:])
        except Exception as e:
            new_node = Node(resource[0],parent=base)
            if len(resource) > 1:
                add_to_structure(new_node,resource[1:])
    except Exception as e:
        return {'web_structure':e}

def render_tree(root):
    result = ''
    for pre, _, node in RenderTree(root,style=DoubleStyle):
        result += ('%s%s' % (pre, node.name))
        result += '\n'
    return result


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
	        url = line[f_char_index:l_char_index]
                if not url.startswith('http') and not url.startswith('//'):
        	        resource = url.split('/')
        	        add_to_structure(tree,resource)
        if indexes2 != []:
	    for index in indexes1:
	        f_char_index = index + 6    
	        l_char_index = line[f_char_index:].index('"') + f_char_index  
	        url = line[f_char_index:l_char_index]
                if not url.startswith('http') and not url.startswith('//'):
        	        resource = url.split('/')
        	        add_to_structure(tree,resource)


def map_server(site, url):
    try:
        response = get(url, verify=False, timeout=6)
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
Calls the other functions tog get info from the server
"""
def active_analysis(site, port, protocol):
    try:
        if site == '' or port == '':
            return {'active_ip':'Specify an IP address or domain name and a port.', 'active_port':port}
        result_dict = {'result':True}
	url = get_url(site,str(port),protocol)
        web_structure, tree = map_server(site,url)
        result_dict.update(web_structure)

        return result_dict
    except ValueError as e:
        result_dict.update({'error1':e, 'result':True})
        return result_dict
