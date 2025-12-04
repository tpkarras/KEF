# KEF

[![Total Downloads](https://img.shields.io/packagist/dt/tpkarras/kef)](https://packagist.org/packages/tpkarras/kef)
[![Latest Stable Version](https://img.shields.io/packagist/v/tpkarras/kef)](https://packagist.org/packages/tpkarras/kef)
[![PHP Version Required](https://img.shields.io/packagist/dependency-v/tpkarras/kef/php)](https://packagist.org/packages/tpkarras/kef)

**KEF (Karras Encryption Format)** is an encryption format designed for storing encrypted data.

Its intended purpose is to allow applications to be able to retrieve ranges of data without decrypting the entirety of the data.

KEF is released under the GNU General Public License v3.0.

## Installation

If you have composer, you can use the command below.

```sh
composer require tpkarras/kef
```

Otherwise you can extract the files from the "bin" directory and place them anywhere within your PHP project.

## Minimum Requirements

KEF requires a PHP version greater than or equal to 7.4.0.

Memory size is dependent on the buffer size set and the size of the data fed to the encryption function, you can experiment with the "memory_limit" directive found in "php.ini" in order to find the right memory size for your usage needs.

## Documentation

All documentation on how to use KEF and how to implement KEF in your project is available on the [wiki](https://github.com/tpkarras/KEF/wiki).
