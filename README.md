Opauth-Truenth
=============
[Opauth][1] strategy for Truenth authentication.

Implemented based on http://developer.github.com/v3/oauth/ using OAuth2.

Opauth is a multi-provider authentication framework for PHP.

Demo: http://opauth.org/#github

Getting started
----------------
1. Install Opauth-Truenth:
   ```bash
   cd path_to_opauth/Strategy
   git clone git://github.com/uzyn/opauth-truenth.git Truenth
   ```

2. Register a Truenth application at <truenth-portal-url/client>
   - Authorized URL: enter `http://path_to_opauth/truenth/oauth2callback`
   
3. Configure Opauth-Truenth strategy with `client_id` and `client_secret`.

4. Direct user to `http://path_to_opauth/truenth` to authenticate


Strategy configuration
----------------------

Required parameters:

```php
<?php
'GitHub' => array(
	'authorize_url' => 'PORTAL AUTHORIZE URL',
	'access_token_url' => 'PORTAL TOKEN URL',
	'base_url' => 'PORTAL API URL',
	'client_id' => 'YOUR CLIENT ID',
	'client_secret' => 'YOUR CLIENT SECRET'
)
```

Optional parameters:
`scope`, `state`

License
---------
Opauth-Truenth is MIT Licensed  
Copyright © 2015 University of Washington 

[1]: https://github.com/uzyn/opauth
