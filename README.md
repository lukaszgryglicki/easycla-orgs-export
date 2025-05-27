# easycla-orgs-export
Tool for exporing orgs from EasyCLA based on CCLA signatures

# AWS env

```
[MFA=1] [DEBUG=1] [STAGE=prod|dev] . ./setenv.sh.secret
```

Example: `` MFA=1 DEBUG=1 STAGE=prod . ./setenv.sh.secret ``.


# Run export

- For all time: `` ./easycla-orgs-export ``.
- From give date: `` ./easycla-orgs-export 2025-04-17 ``.
