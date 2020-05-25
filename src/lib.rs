mod scheme;
mod storage;

pub use storage::Storage;
pub use scheme::{
    Scheme,
    BasicAuthScheme,
    BasicAuthRequest,
    BearerAuthScheme,
    BearerAuthRequest
};

use std::marker::PhantomData;
use futures::future::BoxFuture;
use tide::{ Middleware, Next, Request, Response };
use tide::{ StatusCode, Result };
use tracing::{info, error};

/// Middleware for implementing a given [`Scheme`] (Basic, Bearer, Jwt) backed by a given
/// [`Storage`] backend implemented by the [Tide application
/// `State`](https://docs.rs/tide/0.9.0/tide/#state).
pub struct Authentication<User: Send + Sync + 'static, ImplScheme: Scheme<User>> {
    pub(crate) scheme: ImplScheme,
    _user_t: PhantomData<User>
}

#[doc(hidden)]
impl<User: Send + Sync + 'static, ImplScheme: Scheme<User>> std::fmt::Debug for Authentication<User, ImplScheme> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        write!(formatter, "Authentication<Scheme>")?;
        Ok(())
    }
}

impl<User: Send + Sync + 'static, ImplScheme: Scheme<User>> Authentication<User, ImplScheme> {
    /// Create a new authentication middleware with a scheme.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> Result<(), std::io::Error> { block_on(async {
    /// #
    /// use tide_http_auth::{ Authentication, BasicAuthScheme };
    /// Authentication::new(BasicAuthScheme::default());
    /// # Ok(()) }
    /// ```
    pub fn new(scheme: ImplScheme) -> Self {
        Self {
            scheme,

            _user_t: PhantomData::default()
        }
    }
}

impl<ImplScheme, State, User> Middleware<State> for Authentication<User, ImplScheme>
    where ImplScheme: Scheme<User> + Send + Sync + 'static,
          State: Storage<User, ImplScheme::Request> + Send + Sync + 'static,
          User: Send + Sync + 'static {
    fn handle<'a>(
        &'a self,
        mut cx: Request<State>,
        next: Next<'a, State>,
    ) -> BoxFuture<'a, Result<Response>> {
        Box::pin(async move {
            // read the header
            let auth_header = cx.header(ImplScheme::header_name());
            if auth_header.is_none() {
                info!("no auth header, proceeding");
                return next.run(cx).await;
            }
            let value: Vec<_> = auth_header.unwrap().into_iter().collect();

            if value.is_empty() {
                info!("empty auth header, proceeding");
                return next.run(cx).await;
            }

            if value.len() > 1 && ImplScheme::should_401_on_multiple_values() {
                error!("multiple auth headers, bailing");
                return Ok(Response::new(StatusCode::Unauthorized));
            }

            for value in value {
                let value = value.as_str();
                if !value.starts_with(ImplScheme::scheme_name()) {
                    continue;
                }
                let auth_param = &value[ImplScheme::scheme_name().len()..];
                let state = cx.state();

                info!("saw auth header, attempting to auth");
                if let Some(user) = self.scheme.authenticate(state, auth_param).await? {
                    cx = cx.set_ext(user);
                    break;
                } else if ImplScheme::should_403_on_bad_auth() {
                    error!("Authorization header sent but no user returned, bailing");
                    return Ok(Response::new(StatusCode::Forbidden));
                }
            }

            return next.run(cx).await;
        })
    }
}
