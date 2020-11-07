Encon is an optionally-encrypted config format, built on top of JSON.

## Install

```sh
npm install encon

# or
yarn add encon
```

## Usage (high level)

TODO: implement and document.

## Usage (low level)

```js
const { Password } = require('encon');

let pass = new Password('strongpassword');

pass.encrypt(Buffer.from('Hello, world!')).then(encrypted => {
  console.log(encrypted.toString('hex'));

  pass.decrypt(encrypted).then(plainBuffer => {
    let plain = plainBuffer.toString();
    console.log(plain); // 'Hello, world!'
  });
});
```