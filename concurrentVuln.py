import sys
import requests
import json
import argparse
import urllib.parse
from urllib.parse import urlparse
#TO-DO Funcion para modificar a futuro los proxy
#def setProxys(http/s,ip) 

cookieFlag = 0

def validateLogin(response):
    #r_dict = response.json()
    #print(r_dict)
    if response.status_code == 200 or response.status_code == 302:
        print("Status code seems ok, checking cookies")

        if setCookieCheck(response) == 1:
            print("Cookie sesion generada")
            print("Login successful")
            print("             ")
            return(1)
        elif contentTieneJson(args.contenttype) == 1:
            if buscarToken(response) == 1:
                print ("Cookie sesion generada")
                print("Login successful")
                print("             ")
                return(1)
        else:
            print("Login failed")
            return(2)
	
    else:
        print("Login failed")
        return(2)

def buscarToken(response):
	r= response.json()
	keys = r.keys()
	#print("busco token")
	for key in keys:
		print(key)
		#print (r[key])		
		rs = r[key]  
		if key == "token" or key== "auth" or key == "authentication":
		    print("Auth Token in response body")			
		    return(1)
		for key2 in rs.keys():
			if key2 == "token" or key2 == "auth" or key2 == "authentication":
				print("Auth Token in response body")			
				#print(r[key][key2])			
				return(1)
	return(2)
#Agregar CookieFlag por si tiene JSESSIONID set cookie o alguna otra por defecto que no sea de auth
def setCookieCheck(response):
	h= response.headers
	global cookieFlag
	cookieF = cookieFlag
	#print("busco set cookie")
	if cookieF == 0: 
		for key in h.keys():  
			if key == "Set-Cookie":
				print("Session Cookie setted with Set-Cookie header")
				return(1) 	
			#print("sigo buscando")
	elif cookieF != 0:
		for key in h.keys():  
			if key == "Set-Cookie":
				cookieF -= 1
				if cookieF == 0:
					print("Session Cookie setted with Set-Cookie header")
					return(1)	
            
	print("No session Set-Cookie header")
	return(2)


def contentTieneJson(header):
    if header.find("json") >= 0:
        return 1
    else:
        return -1


def obtenerLista(lista):
    with open(lista) as fp:
        lines = fp.read()
        usersParams = lines.split('\n')
        print (usersParams) 

def getContentType(host):
    pagresp = requests.get(host)
    pageHeaders = pagresp.headers
    if pageHeaders['Content-Type'] != None :
        s = pageHeaders['Content-Type']
        type = s.split(';')[0]
        return type
    else:
        return None

def validateConcurrent(response1,ip1,response2,ip2):
    print(ip1.text)
    r1 = validateLogin(response1)
    print("                                         ")
    print("-----------------------------------------")    
    print(ip2.text)
    r2 = validateLogin(response2)
    print("                                         ")
    print("-----------------------------------------")
    print("                      ")
    if r1 == 1 and r2 == 1 and ip1.text != ip2.text:
        print("Concurrent is possible")
    else:
        print("                       ")
        print("Concurrent not possible")

def contentTieneJson(header):
    if header.find("json") >= 0:
        return 1
    else:
        return -1

#revisar URL, obtener RQ body y modificarlo con el user y password proporcionados

def main(args):
    url = args.rquri
    user = args.user
    password = args.password
    parsed_uri = urlparse(url)
    parsedurl= urllib.parse.urlsplit(url)
    host = '{uri.scheme}://{uri.netloc}/'.format(uri=parsed_uri)
    host2 = parsedurl.hostname

    #Proxy de prueba obtenida de https://free-proxy-list.net/, usar elite proxy con https
    proxies = {'https':'http://186.56.99.103:53040'}
    proxyburp = {"http": "http://127.0.0.1:8087", "https": "http://127.0.0.1:8087"}
    #Defino por defecto parametros
    userfield = "username"
    passwordfield ="password"
    ctStatus = None

    #Verificacion si hay especificacion de RQ 
    if args.userfield != None:
        userfield = args.userfield
    if args.passwordfield != None:
        passwordfield = args.passwordfield
    
    
    if getContentType(host) != None:
        contentType = getContentType(host)
        ctflag = 1
    else:
        ctflag = 0
	
    global cookieFlag
    cookieFlag = 0
    
    
    data={userfield:user,passwordfield:password}

    pagresp = requests.get(host)
    pageHeaders = pagresp.headers
    contentType = pageHeaders['Content-Type']
    
    if args.contenttype != None:
        contentType = args.contenttype
        ctflag = 1
    
    #Chequeo si hay algun set-cookie de sesion previo al de autorizacion 
    try:
        if pageHeaders['Set-Cookie'] != None :
            s = pageHeaders['Set-Cookie']
            cookie = s.split(';')[0]
            cookie = cookie+";"
            #print("La cookie es:  "+cookie)
            #print("El content es:  "+contentType)
            #if ctStatus != None :    
            headers ={'Host':host2,'content-type':contentType,'Cookie':cookie}
            #else:
            #    headers ={'Host':host, 'Cookie':cookie}

            cookieFlag += 1
    except:
        headers ={'Host':host2}
        #, 'content-type':contentType}

    print("                                         ")
    print("-----------------------------------------")
    print("                                         ")
    #print(pageHeaders['Content-Type'])
    
    if contentTieneJson(contentType) == 1 :	
    	response1 = requests.post(url,headers=headers,json=data)
    	response2 = requests.post(url,headers=headers,json=data,proxies=proxies)
    	#validateLogin(response1)
    	

    else:
    	response1 = requests.post(url,headers=headers,data=data)
    	response2 = requests.post(url,headers=headers,data=data,proxies=proxies)
    	#validateLogin(response2)
    	#validateLogin(response1)
   
    	
    ip1 = requests.get("https://ipecho.net/plain")
    ip2 = requests.get("https://ipecho.net/plain",proxies=proxies)

    print("                                         ")
    print("                                         ")
    print("-----------------------------------------")
    print("                                         ")
    validateConcurrent(response1,ip1,response2,ip2)
    #buscarToken(response1)



if __name__== "__main__":
    parser = argparse.ArgumentParser(description='Usage of concurrent.py')
    parser.add_argument('-ur','--rquri',type=str,help='URI of the login RQ')
    parser.add_argument('-u','--user',type=str,help='Username for login attempt')
    parser.add_argument('-p','--password',type=str,help='Password for login attempt')
    parser.add_argument('-uf','--userfield',type=str,help='User field for Request, default: username')
    parser.add_argument('-pf','--passwordfield',type=str,help='Password field for Request, default: username')
    parser.add_argument('-px','--proxy',type=str,help='Proxy IP to use')
    parser.add_argument('-ct','--contenttype',type=str,help='Content-type of Request')
    args = parser.parse_args()
    main(args)
