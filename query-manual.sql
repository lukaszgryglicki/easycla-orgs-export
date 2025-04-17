SELECT DISTINCT
  COALESCE(c.data:company_name, s.data:signature_reference_name, '') AS company,
  s.data
FROM
  {{.Signatures}} s
LEFT JOIN
  {{.Companies}} c
ON
  s.data:signature_reference_id = c.company_id
WHERE
  s.data:signature_type = 'ccla'
  AND s.data:signature_signed
  AND s.data:signature_approved
  AND LOWER(COALESCE(s.data:note, '')) LIKE 'manually added%'
  AND s.data:date_created >= ?
