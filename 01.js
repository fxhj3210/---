var total = 0 ;
var successTotal = [0,0] ;
var url = "/api/challenge1";
    call = function(num) {
        var list = {
            "page": String(num),
        };
        $.ajax({
            url: url,
            dataType: "json",
            async: true,
            data: list,
            type: "POST",
            beforeSend: function(request) {
                var a = '9622';
                var timestamp = String(Date.parse(new Date()) / 1000);
                var tokens = hex_md5(window.btoa(a + timestamp));
                request.setRequestHeader("safe", tokens);
                request.setRequestHeader("timestamp", timestamp)
            },
            success: function(data) {
                var s = '<tr class="odd">';
                datas = data.data;
                $.each(datas, function(index, val) {                    
                    var html = '<td class="info">' + val.value + '</td>';
                    total += parseInt(val.value,10)
                    s += html
                });
                $('.data').text('').append(s + '</tr>')
                successTotal[0] += 1 
                if(successTotal[0]==successTotal[1]){
                   alert(total)
                }
            },
            complete: function() {
                $("#page").paging({
                    nowPage: num,
                    pageNum: 100,
                    buttonNum: 7,
                    canJump: 1,
                    showOne: 1,
                    callback: function(num) {
                        call(num)
                    },
                })
            },
            error: function() {
                alert('检测到异常情况，请关闭抓包工具，使用chrome浏览器再试试');
                location.reload()
            }
        })
    };

for (i = 1; i <= 100; i++) {
  successTotal[1] += 1
  call(i)
}
