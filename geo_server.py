import asyncio
import logging
from aiohttp import web
import geoip2.database
import dns.resolver
from jose import jwt
from functools import wraps
import datetime
import tenacity
import sqlite3


###define logger
logging.basicConfig(filename='geo_server.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')
logger = logging.getLogger(__name__)
###############

###database functions
##create functions
def create_tables():
    # Connect to the SQLite database
        conn = sqlite3.connect('geolocation.db')
        cursor = conn.cursor()

        # Create Requests Table
        cursor.execute('''CREATE TABLE IF NOT EXISTS Requests (
                            id INTEGER PRIMARY KEY,
                            domain_id INTEGER,
                            request_status TEXT,
                            FOREIGN KEY (domain_id) REFERENCES Domains(id)
                            )''')

        # Create Domains Table
        cursor.execute('''CREATE TABLE IF NOT EXISTS Domains (
                            id INTEGER PRIMARY KEY,
                            domain_name TEXT UNIQUE
                            )''')

        # Create Servers Table
        cursor.execute('''CREATE TABLE IF NOT EXISTS Servers (
                            id INTEGER PRIMARY KEY,
                            domain_id INTEGER,
                            server_name TEXT,
                            FOREIGN KEY (domain_id) REFERENCES Domains(id)
                            )''')

        # Create IPAddresses Table
        cursor.execute('''CREATE TABLE IF NOT EXISTS IPAddresses (
                            id INTEGER PRIMARY KEY,
                            server_id INTEGER,
                            ip_address TEXT,
                            country TEXT,
                            region TEXT,
                            FOREIGN KEY (server_id) REFERENCES Servers(id)
                            )''')

        # Commit changes and close connection
        conn.commit()
        conn.close()

##insert functions
def insert_domain_and_request(domain):
    # Connect to the SQLite database
    conn = sqlite3.connect('geolocation.db')
    cursor = conn.cursor()

    # Check if the domain exists in the Domains table
    cursor.execute('''SELECT id FROM Domains WHERE domain_name = ?''', (domain,))
    result = cursor.fetchone()

    if result:
        # Domain exists, get its ID
        domain_id = result[0]
    else:
        # Domain does not exist, insert the new domain
        cursor.execute('''INSERT INTO Domains (domain_name) VALUES (?)''', (domain,))
        conn.commit()
        domain_id = cursor.lastrowid

    # Insert a new request for the domain
    cursor.execute('''INSERT INTO Requests (domain_id, request_status) VALUES (?, ?)''', (domain_id, 'Resolving IPs'))
    conn.commit()
    request_id = cursor.lastrowid

    conn.close()
    return request_id

def insert_server(domain_id, server_name):
    conn = sqlite3.connect('geolocation.db')
    cursor = conn.cursor()
    cursor.execute('''INSERT INTO Servers (domain_id, server_name) VALUES (?, ?)''', (domain_id, server_name))
    logger.info(f"inserted server {server_name} which hosts {domain_id}")
    conn.commit()
    conn.close()

def insert_ip_address(server_id, ip_address, country=None, region=None):
    conn = sqlite3.connect('geolocation.db')
    cursor = conn.cursor()

    # Insert IP address without country and region
    if country is None or region is None:
        cursor.execute('''INSERT INTO IPAddresses (server_id, ip_address) VALUES (?, ?)''',
                       (server_id, ip_address))
    else:
        cursor.execute('''INSERT INTO IPAddresses (server_id, ip_address, country, region) VALUES (?, ?, ?, ?)''',
                       (server_id, ip_address, country, region))
    logger.info(f"inserted ip address {ip_address} which is in {server_id}")
    conn.commit()
    conn.close()

##query functions
def query_domain_by_request(request):
    #get domain for database
    conn = sqlite3.connect('geolocation.db')
    cursor = conn.cursor()

    # Query the domain name based on the request ID
    cursor.execute('''
        SELECT Domains.domain_name
        FROM Requests
        INNER JOIN Domains ON Requests.domain_id = Domains.id
        WHERE Requests.id = ?
    ''', (request,))
    result = cursor.fetchone()

    if result:
        domain = result[0]
        conn.close()
        logger.info(f"request {request} is linked to {domain}")
        return domain
        
    else:
        logger.error(f"No domain found for request ID {request}.")
        conn.close()
        return None

def query_ip_addresses_by_request(request_id):
    conn = sqlite3.connect('geolocation.db')
    cursor = conn.cursor()

    try:
        cursor.execute('''
            SELECT DISTINCT ip.ip_address
            FROM IPAddresses ip
            JOIN Servers s ON ip.server_id = s.server_name
            JOIN Domains d ON s.domain_id = d.domain_name
            JOIN Requests r ON d.id = r.domain_id
            WHERE r.id = ?
        ''', (request_id,))
    
        ip_addresses = cursor.fetchall()
        ip_addresses = [x[0] for x in ip_addresses]
        logger.info(f"fetched IP addresses for request {request_id}: {ip_addresses}")
        return ip_addresses
    except sqlite3.Error as e:
        logger.error(f"Error querying IP addresses for request {request_id}: {e}")
        return None
    finally:
        conn.close()

def query_request_status(request_id):
    conn = sqlite3.connect('geolocation.db')
    cursor = conn.cursor()

    try:
        cursor.execute('''SELECT request_status FROM Requests WHERE id = ?''', (request_id,))
        row = cursor.fetchone()
        if row:
            request_status = row[0]
            logger.info(f"Request status for ID {request_id}: {request_status}")
            return request_status
        else:
            logger.info(f"Request with ID {request_id} not found.")
            return None
    except sqlite3.Error as e:
        logger.error(f"Error querying request status for {request_id}: {e}")

    finally:
        conn.close()
        
def query_countries_by_request(request_id):
    conn = sqlite3.connect('geolocation.db')
    cursor = conn.cursor()

    try:
        # Query the IPAddresses table to get country and region based on server ID
        cursor.execute('''
            SELECT DISTINCT ip.country, ip.region
            FROM IPAddresses ip
            JOIN Servers s ON ip.server_id = s.server_name
            JOIN Domains d ON s.domain_id = d.domain_name
            JOIN Requests r ON d.id = r.domain_id
            WHERE r.id = ?
        ''', (request_id,))
        country_region_pairs = cursor.fetchall()
        country_region_pairs = [list(x) for x in country_region_pairs]
        for location in country_region_pairs:
            if location[0] == None:
                location[0] = 'Unspecified Country'
            if location[1] == None:
                location[1] = 'Unspecified Region'
        return country_region_pairs
    except sqlite3.Error as e:
        logger.error(f"Error querying countries by request {request_id}: {e}")
    finally:
        conn.close()
        
def query_domains_by_country(country):
    conn = sqlite3.connect('geolocation.db')
    cursor = conn.cursor()

    try:
        # Query the Domains table to get domains based on servers in the specified country
        cursor.execute('''
            SELECT DISTINCT d.domain_name
            FROM Domains d
            JOIN Servers s ON d.domain_name = s.domain_id
            JOIN IPAddresses ip ON s.server_name = ip.server_id
            WHERE ip.country = ?
        ''', (country,))
        domains = cursor.fetchall()
        domains = [x[0] for x in domains]
        return domains
    except sqlite3.Error as e:
        print(f"Error querying domains by country {country}: {e}")
        return None
    finally:
        conn.close()
        
def query_domains_by_server(server_name):
    conn = sqlite3.connect('geolocation.db')
    cursor = conn.cursor()

    try:
        # Query the Domains table to get domains mapped to the specified server
        cursor.execute('''
            SELECT DISTINCT d.domain_name
            FROM Domains d
            JOIN Servers s ON d.domain_name = s.domain_id
            WHERE s.server_name = ?
        ''', (server_name,))
        domains = cursor.fetchall()

        return domains
    except sqlite3.Error as e:
        logger.error(f"Error querying domains by serve {server_name}: {e}")
        return None
    finally:
        conn.close()

def query_top_domains(n):
    conn = sqlite3.connect('geolocation.db')
    cursor = conn.cursor()

    try:
        cursor.execute('''
            SELECT d.domain_name, COUNT(r.id) AS domain_count
            FROM Domains d
            JOIN Requests r ON d.id = r.domain_id
            GROUP BY d.domain_name
            ORDER BY domain_count DESC
            LIMIT ?
        ''', (n,))
    
        domain_counts = cursor.fetchall()
        logger.info(f"domain occurences: {domain_counts}")
        top_domains = domain_counts[:n]
        return top_domains
    except sqlite3.Error as e:
        logger.error(f"Error counting domain occurrences: {e}")
        return None
    finally:
        conn.close()

def query_top_servers(n):
    conn = sqlite3.connect('geolocation.db')
    cursor = conn.cursor()

    try:
        cursor.execute('''
            SELECT s.server_name, COUNT(*) AS server_count
            FROM Servers s
            GROUP BY s.server_name
            ORDER BY server_count DESC
            LIMIT ?
        ''', (n,))
    
        popular_servers = cursor.fetchall()
        logger.info(f"the {n} most popular servers are {popular_servers}")
        return popular_servers
    except sqlite3.Error as e:
        logger.error(f"Error fetching most popular servers: {e}")
        return None
    finally:
        conn.close()
        
def query_incomplete_requests():
    conn = sqlite3.connect('geolocation.db')
    cursor = conn.cursor()

    try:
        cursor.execute('''
            SELECT *
            FROM Requests
            WHERE request_status != 'complete'
        ''')
    
        incomplete_requests = cursor.fetchall()
        return incomplete_requests
    except sqlite3.Error as e:
        print(f"Error fetching incomplete requests: {e}")
        return None
    finally:
        conn.close()

##update functions
def update_request_status(request_id, status):
    conn = sqlite3.connect('geolocation.db')
    cursor = conn.cursor()

    try:
        cursor.execute('''UPDATE Requests SET request_status = ? WHERE id = ?''',
                       (status, request_id))
        conn.commit()
        logger.info(f"Request with ID {request_id} status updated to {status}.")
    except sqlite3.Error as e:
        logger.error(f"Error updating request {request_id} status to {status}: {e}")
    finally:
        conn.close()
        
def update_ip_address_location(ip_address, country, region):
    conn = sqlite3.connect('geolocation.db')
    cursor = conn.cursor()

    try:
        cursor.execute('''UPDATE IPAddresses SET country = ?, region = ?
                          WHERE ip_address = ?''', (country, region, ip_address))
        conn.commit()
        logger.info(f"IP address location updated successfully for IP {ip_address} with {country}/{region}.")
    except sqlite3.Error as e:
        logger.error(f"Error updating IP address location for IP {ip_address}: {e}")
    finally:
        conn.close()


###############

###handle login and resolve unfinished queries
SECRET_KEY = 'VeniceSimplon'

async def handle_login(request):
    data = await request.post()
    username = data.get('username')
    password = data.get('password')

    #validate username and password

    if username == 'admin' and password == 'admin_password':
        logger.info(f"successful login")
        
        #create a token that will expire after a day
        payload = {
        'username': username,
        'exp': datetime.datetime.now() + datetime.timedelta(days=1)  # Token expires in 1 day
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
        logger.info(f"token created, token: {token}")
        
        #resolve unfinished requests after successful login
        await resolve_unfinished_requests()
        
        return web.json_response({'token': token})
    else:
        logger.error(f"Invalid credentials, client tried username: {username}, password: {[password]}")
        return web.json_response("Invalid credentials.", status=401)

def token_required(handler):
    @wraps(handler)
    async def wrapper(request):
        token = request.headers.get('Authorization')
        #validate response
        if not token:
            logger.error(f"Token is missing")
            return web.json_response("Token is missing.", status=401)

        #decode token and allow use
        try:
            token = token.replace('Bearer ', '')

            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            logger.info(f"token decoded")
            request.user = payload['username']
        
        #handle exceptions due to token expiration or invalid token
        except jwt.ExpiredSignatureError:
            logger.error(f"Token has expired")
            return web.json_response("Token has expired.", status=401)
        
        except jwt.InvalidTokenError:
            logger.error(f"Invalid token")
            return web.json_response("Invalid token.", status=401)

        return await handler(request)

    return wrapper

async def resolve_unfinished_requests():
    #look up all the unfinished request that might have been interrupted due to internet failure or crash
    unfinished_requests = query_incomplete_requests()
    for unfinished in unfinished_requests:
        status  = unfinished[2]
        request = unfinished[0]
        if status == 'Resolving IPs':
            logger.info(f"request {request} was not finished, continuing from get_ips")
            await get_ips(request)
        if status == 'Resolving Countries':
            logger.info(f"request {request} was not finished, continuing from get_location")
            await get_location(request)

app = web.Application()
###############
###handle geolocatio requests
@token_required
async def geolocation_request_handler(request):
    domain = request.query.get('domain')
    #validate the response
    if not domain:
        logger.error("Domain not provided in geolocation request.")
        return web.json_response(text="Domain not provided.", status=400)

    #insert the request and the domain to the database
    request_id = insert_domain_and_request(domain)
    if request_id == None:
        return web.json_response(f"Problem inserting domain {domain}.", status=404)
    
    await get_ips(request_id)
    logger.info(f"generated request id and it is {request_id}")
    return web.json_response({'request_id': request_id})

##get the IP addresses and servers of a request
@tenacity.retry(wait=tenacity.wait_exponential(), stop=tenacity.stop_after_attempt(3))
async def get_ips(request):
    #query domain by request
    domain = query_domain_by_request(request)
    
    #log if the domain wasn't found
    if domain == None:
        logger.error(f"Could not find a domain for request {request}.")
    
    
    try:
        #resolve the servers for the domain
        answers = dns.resolver.resolve(domain, 'NS')
        serverslist = [str(answer) for answer in answers]
        
        
        for server in serverslist:
            #insert the server to the database
            insert_server(domain, server)
            
            #resolve IP addresses for each server
            ips = dns.resolver.resolve(server, 'A')
            ipslist = [str(ip) for ip in ips]
            for ip in ipslist:
                #insert the IP addresses to the database
                insert_ip_address(server, ip)
            
            
        #after finishing resolving the location update the request status   
        update_request_status(request, 'Resolving Countries')
        logger.info(f"resolved IPs for all the servers for request id {request}.")
    
    #update the request status if the IP was not found or if there was an error
    except dns.resolver.NXDOMAIN as e:
        update_request_status(request, 'IPs not found')
        logger.error(f"IPs not found in the database for request id {request}.")
        return web.json_response({'error message': 'IPs not found'}, status=404)
    
    except Exception as e:
        update_request_status(request, 'IPs not found due to an error')
        logger.error(f"an error occured during get_ips() for request id {request}.")
        return web.json_response({'error message': f"An error occured during get IPs, {e}"}, status=500)
    
    await get_location(request)

##get the location of a request        
async def get_location(request):
    
    #initialize GeoIP2 reader with the GeoLite2-City database
    geo_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
    
    try:
        #query all the IP addresses of the request
        ips = query_ip_addresses_by_request(request)
        if ips == None:
            logger.error(f"Error querying IP addresses for request {request}")
        logger.info(f"IPs for request {request} are: {ips}")
        
        #update the locations of the IP addresses
        for ip in ips:
            response = geo_reader.city(ip)
            country = response.country.name
            region = response.subdivisions.most_specific.name
            location = f"{country}/{region}"
            update_ip_address_location(ip, country, region)
            logger.info(f"the location of IP {ip} is {location}")
        
        #update request status to complete    
        update_request_status(request, 'complete')
        logger.info(f"resolved geolocations for each IP for request id: {request}.")
        return web.json_response({'request_id': request})
    
    except geoip2.errors.AddressNotFoundError:
        #update request status to Geolocation not found
        update_request_status(request, 'Geolocation data not found')
        logger.error(f"Geolocation data not found for request id: {request}.")
        return web.json_response("Geolocation data not found.", status=404)
    
    finally:
        geo_reader.close()

##get the status of a request (locations will be presented if it complete)
@token_required
async def request_status_handler(request):
    request = request.query.get('request_id', 0)
    #validate the response
    if not request.isnumeric():
        logger.error(f"the request {request} was not numeric in request_status_handler")
        return web.json_response("request is not numeric, enter a number bigger than 0.", status=400)
    request = int(request)
    if request < 1:
        logger.error("request is smaller than 1")
        return web.json_response("request must be greater than 0.", status=400)
    
    #query the status of the request, present location if complete. if not, present the status.
    status = query_request_status(request)
    
    if status == None:
        logger.error(f"request id {request} was not found in the database when using request_status_handler(request).")
        return web.json_response("Request ID not found.", status=404)
    if status != 'complete':
        logger.info(f"request id {request} was not completed, its status is {status}.")
        return web.json_response({'status': status})
    else:
        locations = query_countries_by_request(request)
        if locations == None:
            logger.error(f"error while querying the locations of {request}.")
        logger.info(f"request id {request} was completed, the locations are {locations}.")
        return web.json_response(locations)

##get country domains
@token_required
async def country_domains_handler(request):
    country = request.query.get('country')
    #validating response
    if not country:
        logger.error("country was not provided to country_domains_handler(request).")
        return web.json_response("Country not provided.", status=400)
    
    #querying the domains by country
    domains = query_domains_by_country(country)
    if domains == None:
        logger.info(f"No domain is the system has servers in {country}.")
        return web.json_response(f"No domain is the system has servers in {country}.", status=400)
    else:
        logger.info(f"the following domains are in {country}: {domains}")
        return web.json_response(domains)

##get server domains
@token_required
async def server_domains_handler(request):
    server = request.query.get('server')
    #validating response
    if not server:
        logger.error("server was not provided to server_domains_handler(request).")
        return web.json_response("Server not provided.", status=400)
    
    #querying the domain that belongs to the server
    domains = query_domains_by_server(server)
    if domains == None:
        logger.info(f"No domain is the system is stored in {server}.")
        return web.json_response(f"No domain is the system is stored in {server}.", status=400)
    else:
        logger.info(f"the following domains are stored in {server}: {domains}")
        return web.json_response(domains)

##get the top n popular domains
@token_required
async def popular_domains_handler(request):
    response = request.query.get('n', 5)
    #validate the response
    if not response.isnumeric():
        logger.error("the response was not numeric in popular_domains_handler(request)")
        return web.json_response("response is not numeric, enter a number bigger than 0.", status=400)
    n = int(response)
    if n < 1:
        logger.error("n is smaller than 1")
        return web.json_response("n must be greater than 0.", status=400)

    #query top n popular domains
    top_domains = query_top_domains(n)
    if top_domains == None:
        logger.error(f"there was a problem querying the top {n} popular domains")
        return web.json_response({'message': f"there was a problem querying the top {n} popular domains"})
    
    logger.info(f"the top popular {n} domains in the system are: {top_domains}")
    return web.json_response(top_domains)

##get the top n poplar servers
@token_required
async def popular_servers_handler(request):
    response = request.query.get('n', 5)
    #validate the response
    if not response.isnumeric():
        logger.error("the response was not numeric in popular_servers_handler(request)")
        return web.json_response("response is not numeric, enter a number bigger than 0.", status=400)
    n = int(response)
    if n < 1:
        logger.error("n is smaller than 1")
        return web.json_response("n must be greater than 0.", status=400)
    
    #query top n popular server
    top_servers = query_top_servers(n)
    if top_servers == None:
        logger.error(f"there was a problem querying {n} top servers")
        return web.json_response(f"there was a problem querying {n} top servers")    
    logger.info(f"the top popular {n} servers in the system are: {top_servers}")
    return web.json_response(top_servers)

###############

#define routes
app.router.add_get('/geolocation', geolocation_request_handler)
app.router.add_get('/request_status', request_status_handler)
app.router.add_get('/country_domains', country_domains_handler)
app.router.add_get('/server_domains', server_domains_handler)
app.router.add_get('/popular_domains', popular_domains_handler)
app.router.add_get('/popular_servers', popular_servers_handler)
app.router.add_post('/login', handle_login)

if __name__ == '__main__':
    logger.info(f"starting a new session of the server")
    #create tables if not already created
    create_tables()
    #start the server
    web.run_app(app)

