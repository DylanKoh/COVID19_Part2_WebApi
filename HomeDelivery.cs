//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated from a template.
//
//     Manual changes to this file may cause unexpected behavior in your application.
//     Manual changes to this file will be overwritten if the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace COVID19_Part2_WebApi
{
    using System;
    using System.Collections.Generic;
    
    public partial class HomeDelivery
    {
        public int ID { get; set; }
        public string FullName { get; set; }
        public System.DateTime DateInfected { get; set; }
        public string Address { get; set; }
        public string PostalCode { get; set; }
        public int AddedByUserID { get; set; }
        public System.DateTime AddedDate { get; set; }
        public System.DateTime LastDelivery { get; set; }
        public int MasksRequired { get; set; }
        public byte PriorityID { get; set; }
    
        public virtual LoginUser LoginUser { get; set; }
        public virtual LoginUser LoginUser1 { get; set; }
        public virtual StatusPriority StatusPriority { get; set; }
    }
}