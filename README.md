# XRP Ledger UNL Manager

Tool to validate, compare and sign UNL's.

## Description

This tool allows you to `load`, `compare` (two) and `sign` UNL's.

### Load

The command allows for either a url or a file path:

`./xrpl-unl-manager load {unl_url_or_path}`.

And loads the given UNL performing validations on manifests.

Example request:

`./xrpl-unl-manager load https://vl.xrplf.org` or `./xrpl-unl-manager load /dev/unl.json`.

Example response:

```
There are 35 validators in this UNL. Sequence is: 2024103001 

Validator: ED13AAFCB6A87BCB5D093C2EF37F04431C291126D674293305152D9776C6ABA4D6 (nHBWa56Vr7csoFcCnEPzCCKVvnDQw3L28mATgHYQMGtbEfUjuYyB) | Master: ✓, Signing: ✓ | xrp.vet
Validator: ED4246AA3AE9D29863944800CCA91829E4447498A20CD9C3973A6B59346C75AB95 (nHBidG3pZK11zQD6kpNDoAhDxH6WLGui6ZxSbUx7LSqLHsgzMPec) | Master: ✓, Signing: ✓ |  
Validator: ED5784A43AA84B5BDAFD0AFEF64ADA5583A3129182C6A7464950FD6BF2D9FAE5B0 (nHUryiyDqEtyWVtFG24AAhaYjMf9FRLietbGzviF3piJsMm9qyDR) | Master: ✓, Signing: ✓ |  
Validator: ED583ECD06C3B7369980E65C78C440A529300F557ED81256283F7DD5AA3513A334 (nHUpJSKQTZdB1TDkbCREMuf8vEqFkk84BcvZDhsQsDufFDQVajam) | Master: ✓, Signing: ✓ |  
Validator: ED65142881189CA8FE8D246A8EACE7637A8CA7CE78656638C6D87FAD369F8A5C81 (nHUfxETNHsA9reyYCVYwNztEbifMg6U9YUdcgVvzMwGNpphKSSf6) | Master: ✓, Signing: ✓ | xrpkuwait.com
Validator: ED7098772471769E82A5466329967DC8BF51C941190164E88D7CC9C393AD407C52 (nHUDpRzvY8fSRfQkmJMqjmVSaFmMEVxBNn2tNQy5VAhFJ6is6GFk) | Master: ✓, Signing: ✓ | ekiserrepe.es
Validator: ED8252C2F91523126EEF9A21964C7E487A10D6D63D459139700DBC70D9F7BAD542 (nHULqGBkJtWeNFjhTzYeAsHA3qKKS7HoBh8CV3BAGTGMZuepEhWC) | Master: ✓, Signing: ✓ |  
Validator: EDA4074FD039407BD2464F14C378440D5B02CA8FBA661B286D1C82A3D59E8E6EC0 (nHUbgDd63HiuP68VRWazKwZRzS61N37K3NbfQaZLhSQ24LGGmjtn) | Master: ✓, Signing: ✓ |  
Validator: EDFE65FB385B6BB16951153D2A0F32BD6D8CC4532C87BB3E1900913A7BE34F5EF7 (nHDH7bQJpVfDhVSqdui3Z8GPvKEBQpo6AKHcnXe21zoD4nABA6xj) | Master: ✓, Signing: ✓ |  
Validator: EDC1897CE83B6DCF58858574EC9FE027D4B1538A0F20823800A5529E121E87A93B (nHUFCyRCrUjvtZmKiLeF8ReopzKuUoKeDeXo3wEUBVSaawzcSBpW) | Master: ✓, Signing: ✓ |  
Validator: EDC2A138B3771C208965596D4D372331C17A5476BD2CE2BC7A6D3CD273DF330D99 (nHUq9tJvSyoXQKhRytuWeydpPjvTz3M9GfUpEqfsg9xsewM7KkkK) | Master: ✓, Signing: ✓ |  
Validator: ED38B0288EA240B4CDEC18A1A6289EB49007E4EBC0DE944803EB7EF141C5664073 (nHB8QMKGt9VB4Vg71VszjBVQnDW3v3QudM4DwFaJfy96bj4Pv9fA) | Master: ✓, Signing: ✓ | bithomp.com
Validator: ED135050AE848C37B894EFC67BBEC54A5B4CBAA2281C9DB2D7754A3DF6195DA65E (nHBVACxZaNbUjZZkBfj7gRxF3xgG2vbcP4m48KzVwntdTogi5Tfs) | Master: ✓, Signing: ✓ | onxrp.com
Validator: ED2C5C95F6B67357282B7F1675AFBBAACFB61DF06DEEDF986166E7ADD3D7D33462 (nHBgyVGAEhgU6GoEqoriKmkNBjzhy6WJhX9Z7cZ71yJbv28dzvVN) | Master: ✓, Signing: ✓ | v2.xrpl-commons.org
Validator: ED571031CEB567106CD4E128D46E4DD4087DA12DA9FAB78EEFF7A93971DCC59900 (nHUr8EhgKeTc9ESNt4nMYzWC2Pu7GgRHMRTsNEyGBTCfnHPxmXcm) | Master: ✓, Signing: ✓ | anodos.finance
Validator: ED6A54975A94EB9715E4F4E3FCD1661FCD40C065E6C22E461FEE87267DD73A2D6A (nHUwGQrfZfieeLFeGRdGnAmGpHBCZq9wvm5c59wTc2JhJMjoXmd8) | Master: ✓, Signing: ✓ | xrpgoat.com
Validator: ED95C5172B2AD7D39434EEBC436B65B3BB7E58D5C1CEFC820B6972ACAD776E286A (nHUVPzAmAmQ2QSc4oE1iLfsGi17qN2ado8PhxvgEkou76FLxAz7C) | Master: ✓, Signing: ✓ | ripple.ittc.ku.edu
Validator: ED9DA743B769045A91AC41CA5C56FBD090168CB771E9558DD9D1C4FE8B3F4C842E (nHUY14bKLLm72ukzo2t6AVnQiu4bCd1jkimwWyJk3txvLeGhvro5) | Master: ✓, Signing: ✓ | validator.gatehub.net
Validator: EDA1EFC81058EECB48DEB4FEB7FAFACEAEA42C3E00C0BFB31F85EC116F31A13DAD (nHU2k8Po4dgygiQUG8wAADMk9RqkrActeKwsaC9MdtJ9KBvcpVji) | Master: ✓, Signing: ✓ | verum.eminence.im
Validator: EDAF4CBCF4A9BEE306646549301E22770D5E62D8C03DD9FF42B65A83B2BE1C70F3 (nHUge3GFusbqmfYAJjxfKgm2j4JXGxrRsfYMcEViHrFSzQDdk5Hq) | Master: ✓, Signing: ✓ | katczynski.net
Validator: EDF10074F5FBBB975A8EA8E9C42306854E6A49C71B7D33B0293AB1830FECF2C400 (nHDB2PAPYqF86j9j3c6w1F1ZqwvQfiWcFShZ9Pokg9q4ohNDSkAz) | Master: ✓, Signing: ✓ | xrpscan.com
Validator: ED55BB5A2C8E040367DBA0BA563E924463C360C9C565EFE41701596BA2B828DE16 (nHUrUNXCy4DgPPNABX9C6mUctpoq7CwgLKAUxjw6zYtTfiqsj1ew) | Master: ✓, Signing: ✓ | xrp-validator.interledger.org
Validator: ED580C4282950CB3F7E0185F37F2CFB216882C5EDDD3BB1EE49C304A1AA3C5DB92 (nHUpDPFoCNysckDSHiUBEdDXRu2iYLUgYjTzrj3bde5iDRkNtY8f) | Master: ✓, Signing: ✓ | validator.poli.usp.br
Validator: ED8815A1E647DF83DE643289804F4610464D1ABCF6B38F40404EFA84B5D1A69D81 (nHUP4RcLQdPHh3kMtFm9NFGnjEYLGXiQAyyB7qFsjATHMw2YVxHi) | Master: ✓, Signing: ✓ | xpmarket.com
Validator: EDA8B1D8A071E85A6E36DCAC7999AB814E4CDC664668385173767C5B89554243C0 (nHUdjQgg33FRu88GQDtzLWRw95xKnBurUZcqPpe3qC9XVeBNrHeJ) | Master: ✓, Signing: ✓ | validator.xrpl.robertswarthout.com
Validator: EDCAD6E02AAFF5467465CBB9E62E021BF4B8E23F7484A6F0F67387549733865CCA (nHUtmbn4ALrdU6U8pmd8AMt4qKTdZTbYJ3u1LHyAzXga3Zuopv5Y) | Master: ✓, Signing: ✓ | bifrostwallet.com
Validator: ED63CF929BE85B266A66584B3FE2EB97FC248203F0271DC9C833563E60418E7818 (nHUfPizyJyhAJZzeq3duRVrZmsTZfcLn7yLF5s2adzHdcHMb9HmQ) | Master: ✓, Signing: ✓ | xrp.unic.ac.cy
Validator: EDCF08053DFF0F00AC6E78B61F7B7FD187AF74052DEB5074207506D3A2CDCD9E5C (nHUvcCcmoH1FJMMC6NtF9KKA4LpCWhjsxk2reCQidsp5AHQ7QY9H) | Master: ✓, Signing: ✓ | jon-nilsen.no
Validator: ED580AD4FA5DA989FA999535ECC20197A5B53A1A49A971F6652ED8D5D466CA605D (nHUpDEZX5Zy9auiu4yhDmhirNu6PyB1LvzQEL9Mxmqjr818w663q) | Master: ✓, Signing: ✓ | xspectar.com
Validator: ED6753539020782A777B8F4BF6931A7DB13F9D259486E337C639B99E0C57CD5FF2 (nHU3AenyRuJ4Yei4YHkh6frZg8y2RwXznkMAomUE1ptV5Spvqsih) | Master: ✓, Signing: ✓ | xrpl.aesthetes.art
Validator: EDFF91FA911FE9BF2CCCC2A1F750900C4A6056139FE0DD6872D2A577CA51B27200 (nHDHzXZKtmMHCkTVgdWY4dqdigDrESiseUF8JkzE93DUtfbt6s3W) | Master: ✓, Signing: ✓ | validator.aspired.nz
Validator: ED9AE4F5887BA029EB7C0884486D23CF281975F773F44BD213054219882C411CC7 (nHUXeusfwk61c4xJPneb9Lgy7Ga6DVaVLEyB29ftUdt9k2KxD6Hw) | Master: ✓, Signing: ✓ | validator.xrpl-labs.com
Validator: ED8651B672BCE2727BD93A62431592447D6637E5D0E768595ECC19E5E4AEACAF3B (nHU4bLE3EmSqNwfL4AP1UZeTNPrSPPP6FXLKXo2uqfHuvBQxDVKd) | Master: ✓, Signing: ✓ | ripple.com
Validator: ED75940EC09130F9C553D8AF0FE354A112CC27251472AF1A90917597489192135F (nHUED59jjpQ5QbNhesXMhqii9gA8UfbBmv3i5StgyxG98qjsT4yn) | Master: ✓, Signing: ✓ | arrington-xrp-capital.blockdaemon.com
Validator: EDA54C85F91219FD259134B6B126AD64AE7204B81DD4052510657E1A5697246AD2 (nHUcNC5ni7XjVYfCMe38Rm3KQaq27jw7wJpcUYdo4miWwpNePRTw) | Master: ✓, Signing: ✓ | cabbit.tech

UNL Signature ✓
```

### Compare

The command compares two given UNLs:

`./xrpl-unl-manager compare {unl_1} {unl_2}`.

Example request:

`./xrpl-unl-manager compare https://vl.xrplf.org /dev/unl.json`.

Example response:

```
 https://vl.xrpl.vision (33)
+nHUUgpUVNxXfxkkoyh2QDjfLfHapcut8gYwKeShnJYd3SdPui19A peersyst.cloud
-nHUP4RcLQdPHh3kMtFm9NFGnjEYLGXiQAyyB7qFsjATHMw2YVxHi xpmarket.com
-nHUpJSKQTZdB1TDkbCREMuf8vEqFkk84BcvZDhsQsDufFDQVajam 
-nHDHzXZKtmMHCkTVgdWY4dqdigDrESiseUF8JkzE93DUtfbt6s3W validator.aspired.nz

 https://vl.xrplf.org (35)
+nHUP4RcLQdPHh3kMtFm9NFGnjEYLGXiQAyyB7qFsjATHMw2YVxHi xpmarket.com
+nHUpJSKQTZdB1TDkbCREMuf8vEqFkk84BcvZDhsQsDufFDQVajam 
+nHDHzXZKtmMHCkTVgdWY4dqdigDrESiseUF8JkzE93DUtfbt6s3W validator.aspired.nz
-nHUUgpUVNxXfxkkoyh2QDjfLfHapcut8gYwKeShnJYd3SdPui19A peersyst.cloud
```

### Sign

Signs a new UNL retrieving the secret from AWS.

`./xrpl-unl-manager {manifest} {manifests} {sequence} {expiration_in_days} {aws_secret_name}`

Example request:

`./xrpl-unl-manager sign JAAAAAFxIe0md6v/0bM6xvvDBitx8eg5fBUF4cQsZNEa0bKP9z9HNHMh7V0AnEi5D4odY9X2sx+cY8B3OHNjJvMhARRPtTHmWnAhdkDFcg53dAQS1WDMQDLIs2wwwHpScrUnjp1iZwwTXVXXsaRxLztycioto3JgImGdukXubbrjeqCNU02f7Y/+6w0BcBJA3M0EOU+39hmB8vwfgernXZIDQ1+o0dnuXjX73oDLgsacwXzLBVOdBpSAsJwYD+nW8YaSacOHEsWaPlof05EsAg== test/data/manifests.txt 80 365 test/unl/tool`
