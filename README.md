# Login service

This is an example of a simple authentication service written in go.
The application starts on port 5000. Postgres port is standart: 5432.

## Environment variables

Application support next variables:
* LOG_LEVEL=DEBUG|INFO|WARN|ERROR environment variable for changing log level
* HOST=localhost environment variable for setting application hostname
* PORT=5000 environment variable for setting application port
* DB_HOST=pgdb environment variable for setting database hostname
* DB_PORT=5432 environment variable for setting database port
* DB_USER=postgres environment variable for setting database username
* DB_PASSWORD=pg1234 environment variable for setting database user password
* DB_SSLMODE=disable environment variable for setting database ssl mode

## Data initialization

When application starts, a migration is run and fills the database with user data. In this case, the database takes on the following form:

|id|email|nickname|password|
|:-:|:-:|:-:|:-:|
|30808566-5e58-4a3b-9047-5267830aad2a|user1@email.ru|user1|qZUDsgv742U96FrZsd9wNHr4PM2SY/t7dxhCp/mQhcM=|
|c8710954-bd54-4c59-859e-02fe5f9dd7d2|user2@email.ru|user2|FqFa+EDaXDSU4ZCkEsuemKhswasnfTgJWsGmHG6X8Dg=|
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
$ curl -X DELETE -b 'session_id=...' http://localhost:5000/api/user/{id}/logout
```

Request for get user:

```shell script
$ curl -b 'session_id=...' http://localhost:5000/api/user/{id}
```

Request for get all users:

```shell script
$ curl -b 'session_id=...' http://localhost:5000/api/user/all?limit=10\&offset=10
```

Request for update email:

```shell script
$ curl -X PUT -b 'session_id=...' -d '{"new_email": "newEmail@mail.ru"}' http://localhost:5000/api/user/{id}/update/email
```

Request for update nickname:

```shell script
$ curl -X PUT -b 'session_id=...' -d '{"new_nickname": "newNickname"}' http://localhost:5000/api/user/{id}/update/nickname
```

Request for update password:

```shell script
$ curl -X PUT -b 'session_id=...' -d '{"old_password": "...", "new_password": "..."}' http://localhost:5000/api/user/{id}/update/password
```

Request for delete user:

```shell script
$ curl -X DELETE -b 'session_id=...' http://localhost:5000/api/user/{id}/delete
```
