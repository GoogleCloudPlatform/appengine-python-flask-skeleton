var Events = {

    Action: {
        init: function()
        {
            console.log("Events.Action.init()");
        },

        checkTask: function(){
            $(".tasks-check").change(function(){

                task_id = $(this).attr("id").replace("task-check-", "");
                console.log(task_id)

                if($(this).is(":checked"))
                {

                    $.ajax({
                        url: "/update/task",
                        type: "post",
                        data: {task: task_id, status: "DONE"},
                        success: function(data){
                            console.log(data);
                            $("#tasks-" + task_id).addClass("tasks-done");
                        },
                        error:function(){
                            alert("failure");
                        },
                        dataType: "json"

                    });
                }else{
                    $("#tasks-" + task_id).removeClass("tasks-done");
                    $.ajax({
                        url: "/update/task",
                        type: "post",
                        data: {task: task_id, status: "UNDONE"},
                        success: function(data){
                            console.log(data);
                            $("#tasks-" + task_id).removeClass("tasks-done");
                        },
                        error:function(){
                            alert("failure");
                        },
                        dataType: "json"

                    });
                }

            });
        },
    }
};



