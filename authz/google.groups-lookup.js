const fs = require('fs');
const axios = require('axios');
const jwt = require('jsonwebtoken');

function isAuthorized(decoded, request, callback, unauthorized, internalServerError, config) {
  const googleAuthz = JSON.parse(fs.readFileSync('./google-authz.json'));
  let groupChecks = 0;
  const token = jwt.sign({
    scope: 'https://www.googleapis.com/auth/admin.directory.group.member.readonly'
  },
  googleAuthz.private_key, {
    issuer: googleAuthz.client_email,
    expiresIn: 3600,
    audience: googleAuthz.token_uri,
    subject: config.SERVICE_ACCOUNT_EMAIL,
    algorithm: 'RS256'
  });
  const postData = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    assertion: token
  }).toString();
  axios.post(googleAuthz.token_uri, postData)
    .then(function(response) {
      for (let i = 0; i < googleAuthz.cloudfront_authz_groups.length; i++) {
        const authorization = response.data.token_type + ' ' + response.data.access_token;
        const membershipGet = 'https://www.googleapis.com/admin/directory/v1/groups/' + googleAuthz.cloudfront_authz_groups[i] + '/hasMember/' + decoded.sub;
        console.log(membershipGet + ': ' + authorization);
        axios.get(membershipGet, { headers: {'Authorization': authorization}})
          .then(function(response) {
            groupChecks++;
            if (!response.data.error && response.data.isMember == true && decoded.aud === request.headers.host[0].value && decoded.sub.endsWith(config.HOSTED_DOMAIN)) {
              callback(null, request);
            } else if (groupChecks >= googleAuthz.cloudfront_authz_groups.length) {
              unauthorized('Unauthorized', 'User ' + decoded.sub + ' is not permitted.', '', callback);
            }
          })
          .catch(function(error) {
            groupChecks++;
            if (groupChecks >= googleAuthz.cloudfront_authz_groups.length) {
              unauthorized('Unauthorized.', 'User ' + decoded.sub + ' is not permitted.', '', callback);
            }
          });
      }
    })
    .catch(function(error) {
      internalServerError(callback);
    });
}

function getSubject(decoded) { return decoded.payload.email; }

exports.isAuthorized = isAuthorized;
exports.getSubject = getSubject;
