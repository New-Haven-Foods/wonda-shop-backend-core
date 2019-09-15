# Wonda Shop Backend Core

A RESTful JSON API backend with MongoDB and Postgres database.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine.

### Prerequisites

- Node.js (v8.9.4)
- npm (>= v5.6.0)
- Database: MongoDB, Postgres
	- [Suggested MongoDB installation](https://docs.mongodb.com/manual/installation/)
	- [Suggested Postgres installation](https://postgresapp.com/)

### Installing

```
$ # Install Mongo or/and Postgres by the suggested links above...
$ npm install
```

### Testing Databases CRUD operations

#### MongoDB Driver

```
$ # Start MongoDB daemon...
$ ./examples/database/mongo.sample.js
$ # It should print out the result of each CRUD operations...
```

#### Postgres Driver

```
$ # Start Postgres server...
$ ./examples/database/postgres.sample.js
$ # It should print out the result of each CRUD operations...
```

### Running Server Locally

```
$ # Start MongoDB daemon or/and Postgres server...
$ npm start
```

***[Note] It runs with MongoDB driver by default. Switching to Posgres driver requires only the following one change to any of database strategy object of your choice:***

```
{
  storeType: constants.STORE.TYPES.MONGO_DB, // CHANGE THIS TO `constants.STORE.TYPES.POSTGRES`
  operation: {
    type: constants.STORE.OPERATIONS.SELECT,
    data: [
      { address: state.address }
    ]
  },
  tableName: constants.STORE.TABLE_NAMES.ADDRESS_INFO
}
```

## Testing and Contributing

### Style Lint

```
$ npm run lint
```

### Unit test

```
$ npm run unit-test
```


## Technology

* [Express.js](http://expressjs.com/)
* [node-jsonwebtoken](https://github.com/auth0/node-jsonwebtoken)
* [Sequelize](http://docs.sequelizejs.com/en/latest/)
* [Mongojs](https://github.com/mafintosh/mongojs)

***[Note] All required packages and versions are listed in `package.json`***

## Author

* **Marcus Hsu** - *Initial work*
