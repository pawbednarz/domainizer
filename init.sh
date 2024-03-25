#!/bin/bash

echo -e "THIS SCRIPT SHOULD BE RUN USING SYNTAX source init.sh TO SAVE ENV VARIABLES FOR LATER USE OF APPLICATION";
echo -e "Set environmental variables required for Domainizer to connect to database and run properly";
echo -e "Before running this script, it is required to:";
echo -e "\tInstall postgres";
echo -e "\tCreate database for application";
echo -e "\tCreate postgres user only for Domainizer database, and grant permissions to CREATE, INSERT, UPDATE and DELETE to created database";

echo -e "Enter value for database hostname/IP:";
read db_host;

echo -e "Enter value for database port (postgres default is 5432):";
read db_port;

echo -e "Enter value for database name:";
read db_name;

echo -e "Enter value for database user:";
read db_user;

echo -e "Enter value for database password (it will not be shown in the terminal):";
read -s db_pass;

# set required env variables
export DOMAINIZER_DB_HOST=$db_host;
export DOMAINIZER_DB_PORT=$db_port;
export DOMAINIZER_DB_NAME=$db_name;
export DOMAINIZER_DB_USER=$db_user;
export DOMAINIZER_DB_PASSWORD=$db_pass;
export PGPASSWORD=$db_pass;

echo "export DOMAINIZER_DB_HOST=$db_host;" >> ~/.bashrc
echo "export DOMAINIZER_DB_PORT=$db_port;" >> ~/.bashrc
echo "export DOMAINIZER_DB_NAME=$db_name;" >> ~/.bashrc
echo "export DOMAINIZER_DB_USER=$db_user;" >> ~/.bashrc
echo "export DOMAINIZER_DB_PASSWORD=$db_pass;" >> ~/.bashrc

# create database in postgres
psql -U $db_user -h $db_host -p $db_port -d $db_name -f create.sql

echo -e "Configuration completed. Make sure that you have testssl.sh installed in application directory";
echo -e "In case you want to change any of variables set during configuration, modify them in ~/.bashrc file";