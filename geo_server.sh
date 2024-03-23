#!/bin/bash
python3 geo_server.py &
# Function to perform login and get JWT token
login() {
    echo "======== Initializing Server ========"
    while ! curl -s "http://localhost:8080" > /dev/null; do
        sleep 1
    done

    echo "Enter username:"
    read username
    echo "Enter password:"
    read -s password

    login_response=$(curl -s -X POST http://localhost:8080/login -d "username=$username&password=$password")
    token=$(echo "$login_response" | jq -r '.token')

    if [ -z "$token" ]; then
        echo "Login failed! Please try again."
        login
    else
        echo "Login successful! Token saved."
    fi
}

# Function to execute selected function with argument
execute_function() {
    case $1 in
    1)
        echo "Enter domain for geolocation request:"
        read domain
        curl -s -X GET "http://localhost:8080/geolocation?domain=$domain" -H "Authorization: Bearer $token" | jq
        ;;
    2)
        echo "Enter request ID for status request:"
        read request_id
        curl -s -X GET "http://localhost:8080/request_status?request_id=$request_id" -H "Authorization: Bearer $token" | jq
        ;;
    3)
        echo "Enter a country name to get the domains stored in that country"
        echo "if the country's name is comprised with more than 1 word use '+' between the words"
        echo "for example, to search United States write United+States"
        read country
        curl -s -X GET "http://localhost:8080/country_domains?country=$country" -H "Authorization: Bearer $token" | jq
        ;;
    4)
        echo "Enter a server name for to get the domains stored in that server:"
        read server
        curl -s -X GET "http://localhost:8080/server_domains?server=$server" -H "Authorization: Bearer $token" | jq
        ;;
    5)
        echo "Enter n for n popular domains:"
        read n
        curl -s -X GET "http://localhost:8080/popular_domains?n=$n" -H "Authorization: Bearer $token" | jq
        ;;
    6)
        echo "Enter n for n popular servers:"
        read n
        curl -s -X GET "http://localhost:8080/popular_servers?n=$n" -H "Authorization: Bearer $token" | jq
        ;;
    esac
}

# Main script
login

while true; do
    echo "Select a function to use:"
    echo "1. Geolocation request"
    echo "2. Status request"
    echo "3. Country domains"
    echo "4. Server domains"
    echo "5. N popular domains"
    echo "6. N popular servers"
    echo "Type 'exit' to quit"

    read choice

    case $choice in
    exit)
        echo "Exiting..."
        break
        ;;
    [1-6])
        execute_function $choice
        ;;
    *)
        echo "Invalid choice. Please try again."
        ;;
    esac
done

#close pyhton process
PID=$(lsof -ti:8080)

if [ -z "$PID" ]; then
    echo "No process is currently using port 8080."
else
    echo "Process with PID $PID is using port 8080. Killing the process..."
    kill $PID
    echo "Process killed successfully."
    echo "Finished running."
fi