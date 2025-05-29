SELECT DISTINCT
  COALESCE(c.data:company_name, s.data:signature_reference_name, '') AS company,
  s.signature_id,
  s.data:user_docusign_raw_xml AS doc
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
  AND s.data:user_docusign_raw_xml IS NOT NULL
  AND LOWER(COALESCE(s.data:note, '')) NOT LIKE 'manually added%'
  AND s.data:date_created >= ?
  AND s.data:date_created <= ?
