#' R6 environment to store authentication credentials
#'
#' Used to keep persistent state.
#' @export
BarentsWatchAuth <- R6::R6Class(
  "BarentsWatchAuth",
  public = list(
    token = NULL,
    method = NULL
  ),
  lock_objects = FALSE,
  parent_env = emptyenv()
)


#' Generata BarentsWatch API authentication token
#'
#' Generate a token for the user and the desired scope. The user is sent to the barentswatch authentication page if he/she hasn't given permission to the app yet, else, is sent to the app webpage.
#'
#' @param app_name Name of your developer app
#' @param app_client_id The Client ID of your developer app
#' @param app_secret The secret for your developer app
#'
#' @import httr
#' @import assertthat
#'
#' @export
#' @examples
#' barentswatch_auth(app_name = "APP Name", app_client_id = "App Client ID", app_secret = "APP Secret", token = NULL, new_user = FALSE)
barentswatch_auth <- function(app_name = Sys.getenv("BARENTSWATCH_APP_NAME"), app_client_id = Sys.getenv("BARENTSWATCH_APP_ID"), app_secret = Sys.getenv("BARENTSWATCH_APP_SECRET"), token = NULL, new_user = FALSE){
  if((app_client_id == "" | app_secret == "" | app_name == "") & is.null(token)){
    stop("Need a valid App name, App Client Id and App Secret in order to authorize connection!", call. = FALSE)
  } else {
    Sys.setenv(BARENTSWATCH_APP_NAME = app_name)
    Sys.setenv(BARENTSWATCH_APP_ID = app_client_id)
    Sys.setenv(BARENTSWATCH_APP_SECRET = app_secret)
  }


  checkEnvFile <- function(env){
    value <- Sys.getenv(env)
    value <- ifelse(value == "", return(NULL), return(value))
  }

  options("barentsWatchR.httr_oauth_cache" = ifelse(is.null(getOption("barentsWatchR.httr_oauth_cache")),
                                                    ifelse(is.null(token), "barentswatch.httr-oauth", token),
                                                    getOption("barentsWatchR.httr_oauth_cache")))

  options("barentsWatchR.app_name" = checkEnvFile("BARENTSWATCH_APP_NAME"))
  options("barentsWatchR.app_id" = checkEnvFile("BARENTSWATCH_APP_ID"))
  options("barentsWatchR.app_secret" = checkEnvFile("BARENTSWATCH_APP_SECRET"))


  httr_file <- getOption("barentsWatchR.httr_oauth_cache")


  if(assertthat::is.flag(httr_file)){
    stop("option('barentsWatchR.httr_oauth_cache') must be set to
         valid cache file location,
         not TRUE or FALSE - (example: '.httr-oauth')",
         call. = FALSE)
  }

  assertthat::assert_that(assertthat::is.string(httr_file),
                          assertthat::is.flag(new_user))


  if(new_user){
    rm_old_user_cache(httr_file)
  }


  if(is.null(token)) {     ## supplied no token

    barentswatch_token <- create_barentswatch_token()

  } else if(is.token2.0(token)){     ## supplied a Token object

    legit <- is_legit_token(token)
    if(!legit){
      stop("Invalid token passed to function", call. = FALSE)
    }

    BarentsWatchAuth$set("public", "method", "passed_token", overwrite=TRUE)
    ## set the global session token
    BarentsWatchAuth$set("public", "token", token, overwrite=TRUE)

    ## just return it back
    barentswatch_token <- token

  } else if(assertthat::is.string(token)){ ## a filepath

    if(file.exists(token)){
      barentswatch_token <- read_cache_token(token_path = token)
    } else {
      cat(crayon::red(paste0("No httr_oauth_cache file found at ", token, " - creating new file.\n")))
      options("barentsWatchR.httr_oauth_cache" = token)
      BarentsWatchAuth$set("public", "token", NULL, overwrite=TRUE)
      return(barentswatch_auth(token = NULL))
    }


  } else {
    stop("Unrecognised token object - class ", class(token), call. = FALSE)
  }


  barentswatch_check_existing_token()

  ## return barentswatch_token above
  cat(crayon::green("Successfully authenticated BarentsWatch API!\n"))
  return(invisible(barentswatch_token))


}






#' @noRd
#' @importFrom httr oauth_endpoints oauth_app oauth2.0_token
#' @import httpuv
create_barentswatch_token <- function(){
  check_existing <- barentswatch_check_existing_token()
  if(!check_existing){
    cat(crayon::red("Auto-refresh of token not possible, manual re-authentication required\n"))

    if(!interactive()){
      stop("Authentication options didn't match existing session token and not interactive session
           so unable to manually reauthenticate", call. = FALSE)
    }
  }

  endpoint <- oauth_endpoint(request = "https://www.barentswatch.com/oauth/authorize?",
                             authorize = "https://www.barentswatch.com/oauth/authorize",
                             access = "https://www.barentswatch.com/oauth/token")

  app_name <- getOption("barentsWatchR.app_name", "")
  app_client_id    <- getOption("barentsWatchR.app_id", "")
  app_secret <- getOption("barentsWatchR.app_secret", "")
  cache  <- getOption("barentsWatchR.httr_oauth_cache", "")

  if(app_name == ""){
    stop("option('barentsWatchR.app_name') has not been set", call. = FALSE)
  }

  if(app_client_id == ""){
    stop("option('barentsWatchR.app_id') has not been set", call. = FALSE)
  }

  if(app_secret == ""){
    stop("option('barentsWatchR.app_secret') has not been set", call. = FALSE)
  }

  if(cache == ""){
    stop("option('barentsWatchR.httr_oauth_cache') has not been set", call. = FALSE)
  }

  app <- oauth_app(appname = app_name,
                   key = app_client_id,
                   secret = app_secret)


  barentswatch_token <- oauth2.0_token(endpoint = endpoint,
                                       app = app,
                                       scope = "activity:read_all,profile:read_all",
                                       cache = cache)

  stopifnot(is_legit_token(barentswatch_token))

  BarentsWatchAuth$set("public", "token", barentswatch_token, overwrite=TRUE)
  BarentsWatchAuth$set("public", "method", "new_token", overwrite=TRUE)

  #barentswatch_token
}


#' @noRd
rm_empty_token <- function(token_path = getOption("barentsWatchR.httr_oauth_cache")){
  ## delete token if 0B
  iz_0B <- file.info(token_path)$size == 0
  if(iz_0B){
    unlink(token_path)
  }
}



#' @noRd
rm_old_user_cache <- function(httr_file){
  BarentsWatchAuth$set("public", "token", NULL, overwrite=TRUE)
  if(file.exists(httr_file)){
    cat(crayon::red(paste0("Removing old cached credentials from: ", normalizePath(httr_file),"\n")))
    file.remove(httr_file)
  }
}


#' Reads a token from a filepath
#'
#' Also sets the option of token cache name to the supplied filepath
#'   "barentsWatchR.httr_oauth_cache"
#'
#' httr cache files such as .httr-oauth can hold multiple tokens for different scopes,
#'   this only returns the first one and raises a warning if there are multiple
#'   in the rds file
#' @noRd
#' @import assertthat
read_cache_token <- function(token_path){

  assertthat::assert_that(assertthat::is.readable(token_path))

  cat(crayon::red("Reading token from file path\n"))

  barentswatch_token <- tryCatch({readRDS(token_path)},
                                 error = function(ex){
                                   stop(sprintf("Cannot read token from alleged .rds file:\n%s",
                                                token_path),
                                        ex,
                                        call. = FALSE)
                                 })

  if(is.list(barentswatch_token)){
    cat(crayon::red("Multiple httr-tokens in cache ",token_path, ", only returning first found token\n"))
    barentswatch_token <- barentswatch_token[[1]]
  } else if(is.token2.0(barentswatch_token)){
    cat(crayon::red("Read token successfully from file\n"))
  } else {
    stop("Unknown object read from ", token_path, " of class ", class(barentswatch_token))
  }

  ## for existing tokens, set the options to what is in the token
  barentswatch_token <- overwrite_options(barentswatch_token, token_path = token_path)

  BarentsWatchAuth$set("public", "method", "filepath", overwrite=TRUE)
  ## set the global session token
  BarentsWatchAuth$set("public", "token", barentswatch_token, overwrite=TRUE)

  barentswatch_token
}


barentswatch_token_info <- function(detail_level = getOption("barentsWatchR.verbose", default = 3)){
  token  <- BarentsWatchAuth$public_fields$token
  method <- BarentsWatchAuth$public_fields$method
  message <- ""

  if(is.null(token)){
    message <- c(message, "No token found\n")
    return(NULL)
  }
  if(detail_level >= 3){
    message <- c(message, paste0("Authentication from cache file: ", token$cache_path,"\n"))

  }

  if(detail_level <= 2){
    if(!is.null(token$app$key)){
      message <- c(message, paste0("App key: ", token$app$key,"\n"))
    }

    message <- c(message, paste0("Method: ", method,"\n"))

  }

  if(detail_level == 1){
    message <- c(message, paste0("Hash: ", token$hash(),"\n"))
  }

  cat(crayon::red(message))
}


overwrite_options <- function(barentswatch_token, token_path){
  options("barentsWatchR.httr_oauth_cache" = token_path)
  barentswatch_token$cache_path <- token_path

  if(is.null(barentswatch_token$app)){
    cat(crayon::red("No App Client ID in token\n"))
    return(barentswatch_token)
  }

  if(is.different(barentswatch_token$app$key, "barentsWatchR.app_id")){
    cat(crayon::red(paste0("Overwriting barentsWatchR.app_id from", getOption("barentsWatchR.app_id"),
                           "to ", barentswatch_token$app$key,"\n")))
    options("barentsWatchR.app_id" = barentswatch_token$app$key)
  }

  if(is.different(barentswatch_token$app$secret, "barentsWatchR.app_secret")){
    cat(crayon::red(paste0("Overwriting barentsWatchR.app_secret to ", barentswatch_token$app$secret,"\n")))
    options("barentsWatchR.app_secret" = barentswatch_token$app$secret)
  }

  if(is.different(barentswatch_token$app$appname, "barentsWatchR.app_name")){
    cat(crayon::red(paste0("Overwriting barentsWatchR.app_name to ", barentswatch_token$app$appname,"\n")))
    options("barentsWatchR.app_name" = barentswatch_token$app$appname)
  }

  barentswatch_token

}


is.token2.0 <- function(x){
  inherits(x, "Token2.0")
}



#' Retrieve BarentsWatch token from environment and configs for httr
#'
#' Get token if it's previously stored, else prompt user to get one.
#' @param shiny_return_token In a shiny session, this is passed instead.
#' @return a httr configured option for token
#' For shiny the token is passed from reactive session
#'
#' @keywords internal
#' @family authentication functions
#' @importFrom httr config
get_barentswatch_token <- function(shiny_return_token=NULL) {

  if(any(which(grepl("with_mock_API", as.character(sys.calls()))))){
    cat(crayon::red("Skipping token checks as using with_mock_API\n"))
    return(NULL)
  }

  if(is.null(shiny_return_token)){
    token <- BarentsWatchAuth$public_fields$token

    if(is.null(token) || !is_legit_token(token)) {
      barentswatch_auth()
    }


  } else { #shiny session
    BarentsWatchAuth$set("public", "method", "shiny", overwrite=TRUE)
    token <- shiny_return_token

  }

  config(token = token)

}
