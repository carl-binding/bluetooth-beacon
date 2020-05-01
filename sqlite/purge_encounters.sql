

delete from Encounters
where (last_toc - first_toc < 10) and (last_toc < 120)