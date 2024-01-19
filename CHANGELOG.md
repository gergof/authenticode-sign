# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

## [1.3.0](https://github.com/gergof/authenticode-sign/compare/v1.2.0...v1.3.0) (2024-01-19)


### Features

* Added option to include additional certificates in the certification chain ([27247f9](https://github.com/gergof/authenticode-sign/commit/27247f94cb46bc9bb400c7c90651e28f685d9791))

## [1.2.0](https://github.com/gergof/authenticode-sign/compare/v1.1.1...v1.2.0) (2024-01-18)


### Features

* Added support for nested signatures ([e97c208](https://github.com/gergof/authenticode-sign/commit/e97c2083e68d9b5606e14786c60d45fac1bb2e4c))
* Added support for timestamping the signatures ([7815b69](https://github.com/gergof/authenticode-sign/commit/7815b6922bd44c43a89369950c3ae23f9889e15c))


### Documentation

* Added documentation for signature nesting ([7dc635d](https://github.com/gergof/authenticode-sign/commit/7dc635dca9679d607960c7a81ec6c05456576864))

### [1.1.1](https://github.com/gergof/authenticode-sign/compare/v1.1.0...v1.1.1) (2024-01-17)


### Bug Fixes

* Fixed ESM exports ([091e823](https://github.com/gergof/authenticode-sign/commit/091e8231dd409156a8bcf13be334382548cc5fb7))

## 1.1.0 (2024-01-17)


### Features

* Implemented not-yet-working authenticode signing ([b1ddecf](https://github.com/gergof/authenticode-sign/commit/b1ddecf50ed42bdd23ad479d9c2519d67a49571b))


### Bug Fixes

* Finally got it working ([3ecd202](https://github.com/gergof/authenticode-sign/commit/3ecd2021b8d8c02f3574fb09844aa65663c3c5dd))
* Fixed how the digest for the PEFile is calculated ([c96b46e](https://github.com/gergof/authenticode-sign/commit/c96b46e68faa3f63ae0ae99d56d68f7ebc3e084d))
* Fixed PKCS7 format of signeddata - still not working yet ([c4bc7c2](https://github.com/gergof/authenticode-sign/commit/c4bc7c23f669f173ff330d3aca10359f00fed6f9))
* Fixed Signature format ([312c171](https://github.com/gergof/authenticode-sign/commit/312c171f3696ea541b612199926be71efa78ca1c))


### Improvements

* Changed OID type from number array to string ([687c1c4](https://github.com/gergof/authenticode-sign/commit/687c1c48295a1e85ffd2823892af96595c46cef6))


### Build/CI

* Added drone script ([ea399e0](https://github.com/gergof/authenticode-sign/commit/ea399e0ad4bbce8650a1cbc071a7d7ddd16ffbed))
* Initialized project ([b120222](https://github.com/gergof/authenticode-sign/commit/b1202228c03966c2d500c3bbe368388e8988daaa))


### Documentation

* Added documentation ([98adab4](https://github.com/gergof/authenticode-sign/commit/98adab4b100ff7cffdf00dadace22319d946cbcf))
