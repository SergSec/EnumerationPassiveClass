Este proyecto demuestra cómo realizar **enumeración** sobre un dominio utilizando Python.  
Recoge información pública de **subdominios**, **resolución DNS** y opcionalmente **WHOIS**.

---

## Descripción del proyecto

El script consulta fuentes públicas como **[crt.sh](https://crt.sh)* para identificar subdominios asociados a un dominio principal.  
Después, resuelve cada subdominio encontrado para obtener sus direcciones IP y guarda toda la información en un archivo JSON.

Ejecución:
python enumeracion_pasiva.py tarjet.com
