# Fixture de semgrep --test — no es código del producto.
# Casos de las reglas dockerfile-* de seguridad-ext.yaml. Las anotaciones van
# en líneas separadas porque el chequeo de cobertura del CI captura un solo id
# por anotación. Los USER intermedios evitan que dockerfile-user-root dispare
# sobre los FROM que no son su caso.

# Tag mutable: la imagen cambia debajo de los pies.
# ruleid: dockerfile-mutable-latest-tag
FROM debian:latest
USER servicio
CMD ["./preparar"]

# ruleid: dockerfile-eol-base-image
FROM ubuntu:16.04
# ruleid: dockerfile-add-remote-url
ADD https://ejemplo.invalido/instalador.sh /tmp/instalador.sh
# ruleid: dockerfile-sudo-usage
RUN sudo sh /tmp/instalador.sh
# ruleid: dockerfile-uncleaned-apt-cache
RUN apt-get install -y ca-certificates
# ruleid: dockerfile-privileged-port
EXPOSE 22
USER servicio

# Sin USER de aquí al final: el proceso corre como root.
# ruleid: dockerfile-user-root
FROM node:22-alpine
CMD ["node", "servidor.js"]
