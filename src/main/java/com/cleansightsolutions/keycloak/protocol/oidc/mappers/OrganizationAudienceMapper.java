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

    /*
     * A config which keycloak uses to display a generic dialog to configure the token.
     */
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
        ProviderConfigProperty tokenClaimName = new ProviderConfigProperty();
        tokenClaimName.setName(OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME);
        tokenClaimName.setLabel(OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME_LABEL);
        tokenClaimName.setType(ProviderConfigProperty.STRING_TYPE);
        tokenClaimName.setHelpText(OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME_TOOLTIP);
        tokenClaimName.setDefaultValue("aud");
        configProperties.add(tokenClaimName);

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
        List<String> audiences = orgProvider.getByMember(user)
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

        if (audiences.isEmpty()) {
            return;
        }

        String claimName = mappingModel.getConfig().getOrDefault(
            OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME,
            "aud"
        );

        // Merge with existing aud claim if present
        Object existingAud = token.getOtherClaims().get(claimName);
        Set<String> merged = new HashSet<>(audiences);

        if (existingAud instanceof Collection<?>) {
            ((Collection<?>) existingAud).forEach(a -> merged.add(a.toString()));
        } else if (existingAud instanceof String) {
            merged.add(existingAud.toString());
        }

        token.getOtherClaims().put(claimName, new ArrayList<>(merged));
    }
}
