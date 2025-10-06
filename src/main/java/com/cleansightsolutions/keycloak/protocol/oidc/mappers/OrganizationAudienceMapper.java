package com.cleansightsolutions.keycloak.protocol.oidc.mappers;


import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.organization.OrganizationProvider;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

public class OrganizationAudienceMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper {

    public static final String PROVIDER_ID = "organization-audience-mapper";

    public static final String TOKEN_CLAIM_NAME = "audienceClaimName";

    /*
     * A config which keycloak uses to display a generic dialog to configure the token.
     */
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, OrganizationAudienceMapper.class);
    }

    @Override
    public String getDisplayCategory() {
        return "Token Mapper";
    }

    @Override
    public String getDisplayType() {
        return "Organization Audience Mapper";
    }

    @Override
    public String getHelpText() {
        return "Adds an 'aud' (audience) claim containing organization audience values defined by the 'audience' attribute.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    protected void setClaim(
        IDToken token,
        ProtocolMapperModel mappingModel,
        UserSessionModel userSession,
        KeycloakSession keycloakSession,
        ClientSessionContext clientSessionCtx
    ) {
        UserModel user = userSession.getUser();
        OrganizationProvider orgProvider = keycloakSession.getProvider(OrganizationProvider.class);

        if (orgProvider == null) {
            return;
        }

        // Only include organizations that define an 'audience' attribute
        List<String> audiencesFromOrganizations = orgProvider.getByMember(user)
                .map(orgModel -> {
                    Map<String, List<String>> attributes = orgModel.getAttributes();

                    if(attributes == null) {
                        return null;
                    }

                    List<String> vals = attributes.get("audience");

                    if(vals == null) {
                        return null;
                    }

                    String v = vals.get(0); // Use the first option

                    return (!(v == null | v.isBlank())) ? v : null;
                })
                .filter(Objects::nonNull)
                .filter(aud -> !aud.isBlank())
                .collect(Collectors.toList());

        if (audiencesFromOrganizations.isEmpty()) {
            return;
        }

        // Merge with existing aud claim if present
        new HashSet<>(audiencesFromOrganizations)
            .stream()
            .map(aud -> token.addAudience(aud));
    }
}
