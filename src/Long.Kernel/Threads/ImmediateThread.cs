using Long.Kernel.Managers;
using Quartz;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Long.Kernel.Threads
{
    [DisallowConcurrentExecution]
    public class ImmediateThread : IJob
    {
        public async Task Execute(IJobExecutionContext context)
        {
             await RoleManager.ImmediateTrapsAsync();
        }
    }
}
