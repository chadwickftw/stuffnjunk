import groovy.json.JsonSlurper
import groovy.json.JsonOutput
import org.apache.commons.codec.binary.Hex
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
def id = hostProps.get('lmaccess.id');
def key = hostProps.get('lmaccess.key');
def account = hostProps.get('lmaccount');
def resourcePath = '/alert/alerts';
def args = [:];
args['filter'] = "cleared:*";
args['fields'] = "id,monitorObjectName,monitorObjectId";
def api = new LogicMonitorRestClient(id, key, account)
def alerts = api.get(resourcePath, args)
def resultMap = [:];
// Iterate through most recent alerts
alerts.each{ alert ->
    // Prepare WILDVALUE and WILDALIAS for postprocessing
    monitorObjectId = alert.monitorObjectId;
    monitorObjectName = alert.monitorObjectName.replaceAll('[ :=#.]','_');
    // If this is the first time we are encountering this DataSource ID, create a new map entry
    if(!resultMap.containsKey(monitorObjectId)) {
        // Initialize dictionary to hold relevant alert data
        dict = [:];
        dict['name'] = monitorObjectName;
        dict['alertCount'] = 0;
        // Append data to 
        resultMap["${monitorObjectId}"] = dict;
    }
    resultMap["${monitorObjectId}"]['alertCount']++;
}
// Print each DataSource for Active Discovery
resultMap.each { k, v ->
    println("${k}##${v['name']}");
}
// Write the output to file to reduce number of API calls required
json = JsonOutput.toJson(resultMap);
def fileName = 'deviceAlerts.txt';
file = new File(fileName);
file.write(json);
return 0;
class LogicMonitorRestClient {
    String userKey
    String userId
    String account
    int maxPages = 5;
    int itemsPerPage = 20;
    LogicMonitorRestClient(userId, userKey,  account) {
        this.userId = userId
        this.userKey = userKey
        this.account = account
    }
    def generateHeaders(verb, path) {
        def headers = [:]
        def epoch = System.currentTimeMillis()
        def requestVars = verb + epoch + path
        // Calculate signature
        def hmac = Mac.getInstance('HmacSHA256')
        def secret = new SecretKeySpec(userKey.getBytes(), 'HmacSHA256')
        hmac.init(secret)
        // Sign the request
        def hmac_signed = Hex.encodeHexString(hmac.doFinal(requestVars.getBytes()))
        def signature = hmac_signed.bytes.encodeBase64()
        headers["Authorization"] = "LMv1 " + userId + ":" + signature + ":" + epoch
        headers["Content-Type"] = "application/json"
        //headers["X-Version"] = "2"
        println headers
        return headers
    }
    def packParams(params) {
        def pairs = []
        params.each{ k, v -> pairs << ("${k}=${v}")}
        return pairs.join("&")
    }
    // Non paginating, raw version of the get function
    def _rawGet(path, params) {
        def baseUrl = 'https://' + account + '.logicmonitor.com' + '/santaba/rest' + path
        def packedParams = ""
        if(params) {
            packedParams = "?"+packParams(params)
        }
        def query = baseUrl+packedParams
        println query
        def url = query.toURL()
        def response = url.getText(useCaches: true, allowUserInteraction: false,
                                   requestProperties: generateHeaders("GET", path))
        return response
    }
    // Public interface for getting stuff.
    def get(path, args) {
        def itemsRecieved = []
        def pageReads = 0
        // Impose our own paging parameters.
        args.size = itemsPerPage
        args.offset = 0
        while(true)
        {
            // Do da nastieh
            def response = new JsonSlurper().parseText(_rawGet(path, args))
            if (response.errmsg == "OK")
            {
                itemsRecieved += response.data.items
                // Check if there are more items
                if (response.data.total > itemsRecieved.size())
                {
                    args.offset = response.data.items.size() + args.offset
                }
                else
                {
                    break // we are done
                }
            }
            else
            {
                // Throw an exception with whatever error message we got.
                throw new Exception(response.errmsg)
            }
            pageReads += 1
            // Check that we don't exceed max pages.
            if (pageReads >= maxPages)
            {
                break
            }
        }
        return itemsRecieved
    }
}