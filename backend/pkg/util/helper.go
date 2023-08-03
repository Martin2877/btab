package util

func DeleteSliceItem(nums []string, num string) []string {
	result := make([]string, 0, len(nums))
	for _, v := range nums {
		if v != num {
			result = append(result, v)
		}
	}
	return result
}


func SliceContains(arr []string , keyword string) bool{
	for _,a := range arr{
		if a == keyword {
			return true
		}
	}
	return false
}

func SliceBoolContains(arr []bool , keyword bool) bool{
	for _,a := range arr{
		if a == keyword {
			return true
		}
	}
	return false
}



func RemoveDuplicateElement(languages []string) []string {
	result := make([]string, 0, len(languages))
	temp := map[string]struct{}{}
	for _, item := range languages {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}
