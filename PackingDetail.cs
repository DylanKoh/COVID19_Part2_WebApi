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
    
    public partial class PackingDetail
    {
        public int ID { get; set; }
        public int CentreID { get; set; }
        public System.DateTime PackingDate { get; set; }
        public int PackingQuantity { get; set; }
        public Nullable<bool> AckbyLeadID { get; set; }
        public bool ReadyForCollection { get; set; }
        public bool OutForDelivery { get; set; }
        public Nullable<int> DeliveryID { get; set; }
    
        public virtual Delivery Delivery { get; set; }
        public virtual PackingCentre PackingCentre { get; set; }
    }
}
