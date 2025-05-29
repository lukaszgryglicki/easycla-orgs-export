# easycla-orgs-export
Tool for exporing orgs from EasyCLA based on CCLA signatures

# AWS env

```
[MFA=1] [DEBUG=1] [STAGE=prod|dev] . ./setenv.sh.secret
```

Example: `` MFA=1 DEBUG=1 STAGE=prod . ./setenv.sh.secret ``.


# Run export

- For all time: `` ./easycla-orgs-export ``.
- Until given date: `` ./easycla-orgs-export 2025-04-17 ``.
- For date date: `` ./easycla-orgs-export 2025-05-01 2025-06-01 ``.
