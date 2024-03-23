Hello, in order to start the server you have 2 options:
1. Use the friednly automatic script geo_server.sh
2. Activate the server manually

First, open terminal and navigate to the folder where the geo_server files are located.
In order to install all the dependencies run the install_dependencies.sh script.
You can also install them manually.
Just make sure you have curl and jq commands (you can install it with the following commands (in linux):sudo apt install curl, sudo apt install jq)
Then, make sure you have the following extensions (you can install them with pip):
asyncio
logging
aiohttp
geoip2
dnspython
python-jose
pyjwt
functools
datetime
tenacity
sqlite3

Option 1 - Using The script:

run the script geo_server.sh in your terminal:
./geo_server.sh

enter the following deatils:
username: admin
password: admin_password
in order to login.

then you will be presented with the following menu:
Select a function to use:
1. Geolocation request
2. Status request
3. Country domains
4. Server domains
5. N popular domains
6. N popular servers

type a number between 1-6 for the desired endpoint
according to the endpoint you have chosen, enter the required information (it can be a domain. request id, country name, etc.)

when you are finished type "exit" to quit
you can also quit the program at any time using control+C but it is better to use the exit option since it makes sure the geo_server process is being terminated.

Option 2 - The Manual Options:

Start the server by running geo_server.py in your terminal:
python3 geo_server.py
Open a new terminal window and use a tool like curl or Postman to send HTTP requests to the server.

Login:

curl -s -X POST http://localhost:8080/login -d "username=your_username&password=your_password"
Replace "your_username" with admin and "your_password" with admin_password in order to login.
curl -s -X POST http://localhost:8080/login -d "username=admin&password=admin_password"

you will receive a token, save it in order to access the endpoints

curl commands to test each endpoint:

Geolocation request:

curl -s -X GET "http://localhost:8080/geolocation?domain=<domain"> -H "Authorization: Bearer <token>"
This command will send a GET request to the /geolocation endpoint with the domain parameter set to <domain>, replace <token> with your token.

Request status:

curl -s -X GET "http://localhost:8080/request_status?request_id=<request_id>" -H "Authorization: Bearer <token>"
Replace <request_id> with the actual request ID returned from the geolocation request endpoint, replace <token> with your token.

Country domains:

curl -s -X GET "http://localhost:8080/country_domains?country=<country>" -H "Authorization: Bearer <token>"
This command will retrieve all domains in the system that have servers in <country>, replace <token> with your token.

Server domains:

curl -s -X GET "http://localhost:8080/server_domains?server=<server>" -H "Authorization: Bearer <token>"
This command will retrieve the domain/s in the system that are mapped to the server <server>, replace <token> with your token.

N most popular domains:
curl -s -X GET "http://localhost:8080/popular_domains?n=<n>" -H "Authorization: Bearer $token"
This command will retrieve the n most popular domains in the system. Replace n with your desired number, replace <token> with your token.

N most popular servers:

curl -s -X GET "http://localhost:8080/popular_servers?n=<n>" -H "Authorization: Bearer $token"
This command will retrieve the n most popular servers in the system. Replace n with your desired number, replace <token> with your token.


Additional Information:


Database Schema:
Requests Table:
id (Primary Key)
domain_id (Foreign Key referencing Domains Table)
request_status

Domains Table:
id (Primary Key)
domain_name (Unique)

Servers Table:
id (Primary Key)
domain_id (Foreign Key referencing Domains Table)
server_name

IPAddresses Table:
id (Primary Key)
server_id (Foreign Key referencing Servers Table)
ip_address
country
region

