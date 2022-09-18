# Elytron Credential Store reader example

We know that storing and accessing the user credentials is a hard topic.
These sensitive data must be stored in a secure way.

This example shows how [Elytron](https://wildfly-security.github.io/wildfly-elytron/) Credential Store - that can safely secure sensitive and plain text strings by encrypting them in a storage file - can be access from a JEE application. In this example, the store is protected with an encrypted password.

## Requirements
* Java 11+
* Maven
* [Wildfly 26+](https://www.wildfly.org/)

## How to Set Up Credential Store
Let's assume that we want to create a store named _ExampleCredentialStore_, and we protect it with password _my-store-secret_.
Before creating the Credential Store you have to generate a mask for this password.
Run the following command:
```
user@ubuntu:~/srv/wildfly/bin$ ./elytron-tool.sh mask --salt 12345678 --iteration 100 --secret my-store-secret
```
that will produce the next or similar
```
MASK-1xpIKc1tTnknw8W2VlMRar;12345678;100
```

After starting up the Wildfly standalone you must connect to the Wildfly CLI.
```
user@ubuntu:~/srv/wildfly/bin$ ./jboss-cli.sh
[disconnected /] connect
[standalone@localhost:9990 /]
```

Let's create the example store:
```
/subsystem=elytron/credential-store=ExampleCredentialStore:add(path="csstore.jceks", relative-to=jboss.server.config.dir, credential-reference={clear-text=MASK-1xpIKc1tTnknw8W2VlMRar;12345678;100},create=true)
```
then add a sample user alias to it, for example _my-user-pwd_:
```
/subsystem=elytron/credential-store=ExampleCredentialStore:add-alias(alias=example-pwd, secret-value="my-store-secret")
```

That's all!

## Build and deploy sample app
Execute the following command
```
:~/wildfly-elytron$ mvn clean package
```
then deploy the WAR file into the Wildfly (copy to the wildfly/standalone/deployments).

## How to test
Open you browser or install [httpie](https://httpie.io/) and call the endpoint like
```
http GET localhost:8080/store-example/store/credentials
http GET localhost:8080/store-example/store/credentials/alias/example-pwd
```