#' Get custom API request string
#'
#' Type in your own request string
#'
#' @param request Request string
#'
#' @import httr
#' @import rjson
#'
#'
#' @export
#' @examples
#' barentswatch_customApi(request)
barentswatch_customApi <- function(request){
  tryCatch({
    data <- rjson::fromJSON(rawToChar(GET(request,
                                          config(token = BarentsWatchAuth$public_fields$token))$content))
    if(any(grepl("errors.code",names(unlist(data))))){
      cat(crayon::red("Error: Not an authorized API call"))
    } else{
      return(data)
    }

  }, error = function(e){
    cat(crayon::red("Error: Not an authorized API call"))
  })
}
