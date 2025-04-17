select
  coalesce(c.data:company_name, s.data:signature_reference_name) as company,
  s.data:user_docusign_raw_xml as doc
from
  {{signatures}} s
left join
  {{companies}} c
on
  s.data:signature_reference_id = c.company_id
where
  s.data:signature_type = 'ccla'
  and s.data:signature_signed
  and s.data:signature_approved
  and s.data:user_docusign_raw_xml is not null
  and lower(coalesce(s.data:note, '')) not like 'manually added%'
  and s.data:date_created > 'YYYY-MM-DD'
;
