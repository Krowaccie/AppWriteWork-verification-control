FROM node:24.11.1-bookworm@sha256:9a2ed90cd91b1f3412affe080b62e69b057ba8661d9844e143a6bbd76a23260f
WORKDIR /opt/appwritework/verification-a1
COPY --chown=node:node a1-oci/entrypoint.mjs ./entrypoint.mjs
COPY --chown=node:node a1-oci/base-image.lock.v1.json ./base-image.lock.v1.json
COPY --chown=node:node a1-oci/closure-manifest.v1.json ./closure-manifest.v1.json
COPY --chown=node:node a1-oci/host ./host
COPY --chown=node:node a1-oci/policy ./policy
COPY --chown=node:node a1-oci/probe ./probe
COPY --chown=node:node a1-oci/supervisor-input.v1.json ./supervisor-input.v1.json
COPY --chown=node:node a1-oci/launcher ./launcher
COPY --chown=node:node a1-oci/vendor/actions-artifact/dist ./vendor/actions-artifact/dist
COPY --chown=node:node a1-oci/vendor/actions-artifact/provenance.v1.json ./vendor/actions-artifact/provenance.v1.json
COPY --chown=node:node a1-oci/workspace-parent /work
COPY --chown=node:node --chmod=0555 a1-oci/supervisor/verification-supervisor ./supervisor/verification-supervisor
USER node
ENTRYPOINT ["node", "/opt/appwritework/verification-a1/entrypoint.mjs"]
