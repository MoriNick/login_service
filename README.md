# Login service

This is an example of a simple authentication service written in go.
The application starts on port 5000. Postgres port is standart: 5432.

## Environment variables

Application support next variables:
* JWT_SECRET=string environment variable for signing JWT by HMAC256 method
* LOG_LEVEL=INFO|ERROR environment variable for changing log level

## Data initialization

When application starts, a script is run that fills the database with user data. In this case, the database takes on the following form:

|id|email|nickname|password|
|:-:|:-:|:-:|:-:|
|30808566-5e58-4a3b-9047-5267830aad2a|user1@email.ru|user1|$2a$10$EEHcaSUsTmnoapo8AvMJduvQzaCg3a.lRnUc/dRIvjs3.aYRsILeq|
|c8710954-bd54-4c59-859e-02fe5f9dd7d2|user2@email.ru|user2|$2a$10$48fwG4zmLOtx4k07F/lLIuBczLSNSu8hrzzBZ41biV2B4/9..Hld6|
|...|...|...|...|

Password for users: userN1111 (N - user number)

## Runninig

Build image, create and run containers:

```shell script
$ make
```

Run all unit tests:

```shell script
$ make utests
```

Remove image and containers:

```shell script
$ make docker-clean
```

## API

Request for registration:

```shell script
$ curl -X POST -d '{"email": "user_email@mail.ru", "nickname": "user" "password": "passw"}' http://localhost:5000/api/user/registration
```

Request for login:

```shell script
$ curl -X POST -d '{"param": "email or nickname", "password": "passw"}' http://localhost:5000/api/user/login
```

Request for logout:

```shell script
$ curl -b "access_token=...; refresh_token=..." http://localhost:5000/api/user/{id}/logout
```

Request for get user:

```shell script
$ curl -b "access_token=...; refresh_token=..." http://localhost:5000/api/user/{id}
```

Request for get all users:

```shell script
$ curl -b "access_token=...; refresh_token=..." http://localhost:5000/api/user/all?limit=10\&offset=10
```

Request for update email:

```shell script
$ curl -X POST -b "access_token=...; refresh_token=..." -d '{"new_email": "newEmail@mail.ru"}' http://localhost:5000/api/user/{id}/update/email
```

Request for update nickname:

```shell script
$ curl -X POST -b "access_token=...; refresh_token=..." -d '{"new_nickname": "newNickname"}' http://localhost:5000/api/user/{id}/update/nickname
```

Request for update password:

```shell script
$ curl -X POST -b "access_token=...; refresh_token=..." -d '{"old_password": "...", "new_password": "..."}' http://localhost:5000/api/user/{id}/update/password
```

Request for refresh password:

```shell script
$ curl -X POST -d '{"email": "...", "new_password": "..."}' http://localhost:5000/api/user/password
```

Request for delete user:

```shell script
$ curl -b "access_token=...; refresh_token=..." http://localhost:5000/api/user/{id}/delete
```
