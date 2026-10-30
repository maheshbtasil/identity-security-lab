# Group-Based Authorization

## Configuration

- IAM-Lab-Users grants application assignment to Alice and Bob.
- IAM-Lab-Admins grants access to the application's /admin route.
- Okta supplies membership through the custom ID-token claim lab_groups.
- The application reads the validated claim and stores permitted group names in its server-side session.
- Missing or malformed group claims grant no group permissions.

## Test results

| Test | Status |
| --- | --- |
| Alice accesses /admin through IAM-Lab-Admins membership | Passed |
| Bob signs in and accesses /profile | Passed |
| Bob receives forbidden from /admin | Passed |
| Unauthenticated request to /admin receives 401 | Pending |
| Alice loses /admin access after group removal and fresh login | Pending |

## Security and limitations

Authorization is enforced server-side on each /admin request.
Group membership is captured at login. Changes in Okta do not immediately invalidate an existing application session.
Logout ends the local session and initiates Okta browser-session logout.

## Enterprise IAM relevance

Application assignment and privileged application access are separate entitlements.
This lab demonstrates group-based access decisions relevant to access requests, mover changes, and access reviews.
It is personal lab experience, not production administration.
