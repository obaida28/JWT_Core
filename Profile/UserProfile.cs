public class UserProfile: Profile 
{
    public UserProfile() {
        //in add
        CreateMap < RegisterModel, ApplicationUser > ();
                // .ForMember(dest => dest., opt => opt.Ignore());

        // in show
        // CreateMap < User, UserDTO > ()
        //     .ForMember(
        //         dest => dest.address  ,
        //         opt => opt.MapFrom(src => getAddressAsJson(src.address)));
    }
    //private JsonNode getAddressAsJson(string s){return JsonNode.Parse(s);}
}