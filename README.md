![Verizon Digital Media Services](https://images.verizondigitalmedia.com/2016/03/vdms-30.png)

# ectoken
node.js Token Generator for EdgeCast Token-Based Authentication

## Methods
* **encrypt**(key, params, verbose)
* **decrypt**(key, token, verbose)

## Example
```javascript
const ectoken = require('ectoken').V3;

// encrypt
const token = ectoken.encrypt('keyvalue', 'ec_expire=1257642471&ec_clientip=11.22.33.1');

// decrypt
const params = ectoken.decrypt('keyvalue', token);
```

## License

[View legal and licensing information.](LICENSE)